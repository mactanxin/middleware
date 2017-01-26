#
# Copyright 2016 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import copy
import errno
import gevent
import dockerfile_parse
import dockerhub
import logging
import requests
from gevent.lock import RLock
from gevent.queue import Queue
from resources import Resource
from datetime import datetime, timedelta
from task import Provider, Task, ProgressTask, TaskDescription, TaskException, query, TaskWarning, VerifyException
from cache import EventCacheStore, CacheStore
from datastore.config import ConfigNode
from freenas.utils import normalize, query as q, first_or_default, exclude
from freenas.utils.decorators import throttle
from freenas.dispatcher.rpc import generator, accepts, returns, SchemaHelper as h, RpcException, description, private
from freenas.dispatcher.jsonenc import loads, dumps
from debug import AttachData

logger = logging.getLogger(__name__)
collections = None
images = None
containers_state = None

CONTAINERS_QUERY = 'containerd.docker.query_containers'
NETWORKS_QUERY = 'containerd.docker.query_networks'
IMAGES_QUERY = 'containerd.docker.query_images'

dockerfile_parser_logger = logging.getLogger('dockerfile_parse.parser')
dockerfile_parser_logger.setLevel(logging.ERROR)

docker_names_pattern = '^[a-zA-Z0-9._-]*$'


@description('Provides information about Docker configuration')
class DockerConfigProvider(Provider):
    @description('Returns Docker general configuration')
    @returns(h.ref('docker-config'))
    def get_config(self):
        return ConfigNode('container.docker', self.configstore).__getstate__()


@description('Provides information about Docker container hosts')
class DockerHostProvider(Provider):
    @description('Returns current status of Docker hosts')
    @query('docker-host')
    @generator
    def query(self, filter=None, params=None):
        def extend(obj):
            ret = {
                'id': obj['id'],
                'name': obj['name'],
                'state': 'DOWN',
                'status': None
            }

            try:
                ret['status'] = self.dispatcher.call_sync('containerd.docker.get_host_status', obj['id'])
                ret['state'] = 'UP'
            except RpcException:
                pass

            return ret

        with self.dispatcher.get_lock('vms'):
            results = self.datastore.query_stream('vms', ('config.docker_host', '=', True), callback=extend)
        return q.query(results, *(filter or []), stream=True, **(params or {}))


@description('Provides information about Docker containers')
class DockerContainerProvider(Provider):
    @description('Returns current status of Docker containers')
    @query('docker-container')
    @generator
    def query(self, filter=None, params=None):

        def extend(obj, hosts):
            obj.update({
                'running': containers_state.get(obj['id'], False),
                'reachable': obj['host'] in hosts,
                'hub_url': 'https://hub.docker.com/r/{0}'.format(obj['image'].split(':')[0])
            })
            return obj

        reachable_hosts = list(self.dispatcher.call_sync('docker.host.query', [('state', '=', 'UP')], {'select': 'id'}))

        return q.query(
            self.datastore.query_stream('docker.containers', callback=lambda o: extend(o, reachable_hosts)),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @description('Requests authorization token for a container console')
    @accepts(str)
    @returns(str)
    def request_serial_console(self, id):
        return self.dispatcher.call_sync('containerd.console.request_console', id)

    @description('Creates a new process inside of a container')
    @accepts(str, str)
    @returns(str)
    def create_exec(self, id, command):
        return self.dispatcher.call_sync('containerd.docker.create_exec', id, command)

    @description('Requests interactive console\'s id')
    @accepts(str)
    @returns(str)
    def request_interactive_console(self, id):
        container = self.dispatcher.call_sync('docker.container.query', [('id', '=', id)], {'single': True})
        if not container:
            raise RpcException(errno.ENOENT, 'Container {0} not found'.format(id))

        if container['interactive']:
            return id
        else:
            return self.dispatcher.call_sync('docker.container.create_exec', id, '/bin/sh')


@description('Provides information about Docker networks')
class DockerNetworkProvider(Provider):
    @description('Returns information about Docker networks')
    @query('docker-network')
    @generator
    def query(self, filter=None, params=None):
        hide_builtin_networks = [('name', 'nin', ('bridge', 'external'))]
        if filter:
            filter.extend(hide_builtin_networks)
        else:
            filter = hide_builtin_networks

        return q.query(
            self.datastore.query_stream('docker.networks'),
            *(filter or []),
            stream=True,
            **(params or {})
        )


@description('Provides information about Docker container images')
class DockerImagesProvider(Provider):
    def __init__(self):
        self.throttle_period = timedelta(
            seconds=0, minutes=0, hours=1
        )
        self.collection_cache_lifetime = timedelta(
            seconds=0, minutes=0, hours=24
        )
        self.update_collection_lock = RLock()

    @description('Returns current status of cached Docker container images')
    @query('docker-image')
    @generator
    def query(self, filter=None, params=None):
        return images.query(*(filter or []), stream=True, **(params or {}))

    @description('Returns a result of searching Docker Hub for a specified term - part of image name')
    @accepts(str)
    @returns(h.array(h.ref('docker-hub-image')))
    @generator
    def search(self, term):
        parser = dockerfile_parse.DockerfileParser()

        with dockerhub.DockerHub() as hub:
            for i in hub.search(term):
                presets = None
                icon = None

                if i['is_automated']:
                    # Fetch dockerfile
                    try:
                        parser.content = hub.get_dockerfile(i['repo_name'])
                        presets = self.dispatcher.call_sync('containerd.docker.labels_to_presets', parser.labels)
                    except:
                        pass

                yield {
                    'name': i['repo_name'],
                    'description': i['short_description'],
                    'star_count': i['star_count'],
                    'pull_count': i['pull_count'],
                    'icon': icon,
                    'presets': presets
                }

    @description('Returns a list of docker images from a given collection')
    @returns(h.array(h.ref('docker-hub-image')))
    @accepts(str)
    @generator
    def get_collection_images(self, collection='freenas'):
        def update_collection(c, q):
            parser = dockerfile_parse.DockerfileParser()
            items = []

            with dockerhub.DockerHub() as hub:
                with self.update_collection_lock:
                    try:
                        for i in hub.get_repositories(c):
                            presets = None
                            icon = None
                            repo_name = '{0}/{1}'.format(i['user'], i['name'])

                            if i['is_automated']:
                                # Fetch dockerfile
                                try:
                                    parser.content = hub.get_dockerfile(repo_name)
                                    presets = self.dispatcher.call_sync(
                                        'containerd.docker.labels_to_presets',
                                        parser.labels
                                    )
                                except:
                                    pass

                            item = {
                                'name': repo_name,
                                'description': i['description'],
                                'star_count': i['star_count'],
                                'pull_count': i['pull_count'],
                                'icon': icon,
                                'presets': presets,
                                'version': '0' if not presets else presets.get('version', '0')
                            }
                            items.append(item)
                            q.put(item)
                    except TimeoutError as e:
                        raise RpcException(errno.ETIMEDOUT, e)
                    except ConnectionError as e:
                        raise RpcException(errno.ECONNABORTED, e)
                    finally:
                        q.put(StopIteration)

                    collections.put(c, {
                        'update_time': datetime.now(),
                        'items': items
                    })

        outdated_collections = []
        now = datetime.now()
        for k, v in collections.itervalid():
            time_since_last_update = now - v['update_time']
            if time_since_last_update > self.collection_cache_lifetime:
                outdated_collections.append(k)

        collections.remove_many(outdated_collections)

        collection_data = collections.get(collection, {})
        time_since_last_update = now - collection_data.get('update_time', now)

        if not collections.is_valid(collection) or time_since_last_update > self.throttle_period:
            queue = Queue()
            gevent.spawn(update_collection, collection, queue)
            for i in queue:
                yield i
        else:
            collection_data = collections.get(collection)
            for i in collection_data['items']:
                yield i

    @description('Returns a full description of specified Docker container image')
    @accepts(str)
    @returns(str)
    def readme(self, repo_name):
        with dockerhub.DockerHub() as hub:
            try:
                return hub.get_repository(repo_name).get('full_description')
            except ValueError:
                return None


@description('Provides information about cached Docker container collections')
class DockerCollectionProvider(Provider):
    @description('Returns current status of cached Docker container collections')
    @query('docker-collection')
    @generator
    def full_query(self, filter=None, params=None):
        id_filters = []
        if filter:
            for f in filter:
                if f[0] == 'id':
                    id_filters.append(f)

        if not id_filters:
            raise RpcException(errno.EINVAL, 'Collection entries have to be filtered by id')

        results = list(self.dispatcher.call_sync('docker.collection.query', id_filters))

        for r in results:
            r['images'] = list(self.dispatcher.call_sync('docker.collection.get_entries', r['id']))

        return q.query(results, *(filter or []), stream=True, **(params or {}))

    @description('Returns current status of cached Docker container collections without image entries')
    @query('docker-collection')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream(
            'docker.collections', *(filter or []), **(params or {})
        )

    @description('Returns a list of Docker images related to a saved collection')
    @returns(h.array(h.ref('docker-hub-image')))
    @accepts(str)
    @generator
    def get_entries(self, id):
        collection = self.dispatcher.call_sync('docker.collection.query', [('id', '=', id)], {'single': True})
        if not collection:
            raise RpcException(errno.ENOENT, 'Collection {0} not found'.format(id))

        for i in self.dispatcher.call_sync('docker.image.get_collection_images', collection['collection'], timeout=300):
            if collection['match_expr'] in i['name']:
                yield i


class DockerBaseTask(ProgressTask):
    def get_default_host(self, progress_cb=None):
        if progress_cb:
            progress_cb(0, '')
        hostid = self.dispatcher.call_sync('docker.config.get_config').get('default_host')
        if not hostid:
            hostid = self.datastore.query(
                'vms',
                ('config.docker_host', '=', True),
                single=True,
                select='id'
            )
            if hostid:
                self.run_subtask_sync('docker.config.update', {'default_host': hostid})
                return hostid

            host_name = 'docker_host_' + str(self.dispatcher.call_sync(
                'vm.query', [('name', '~', 'docker_host_')], {'count': True}
            ))

            biggest_volume = self.dispatcher.call_sync(
                'volume.query',
                [('status', '=', 'ONLINE')],
                {'sort': ['-properties.size.parsed'], 'single': True, 'select': 'id'}
            )
            if not biggest_volume:
                raise TaskException(
                    errno.ENOENT,
                    'There are no healthy online pools available. Docker host could not be created.'
                )

            self.run_subtask_sync(
                'vm.create', {
                    'name': host_name,
                    'template': {'name': 'boot2docker'},
                    'target': biggest_volume
                },
                progress_callback=progress_cb
            )

            hostid = self.dispatcher.call_sync(
                'vm.query',
                [('name', '=', host_name)],
                {'single': True, 'select': 'id'}
            )

            self.run_subtask_sync('vm.start', hostid)

        if progress_cb:
            progress_cb(100, 'Found default Docker host')
        return hostid

    def check_host_state(self, hostid):
        host = self.dispatcher.call_sync(
            'docker.host.query',
            [('id', '=', hostid)],
            {'single': True},
            timeout=300
        )

        if not host:
            raise TaskException(errno.ENOENT, 'Docker host {0} does not exist'.format(hostid))

        if host['state'] == 'DOWN':
            raise TaskException(errno.EHOSTDOWN, 'Docker host {0} is down'.format(host['name']))

    def get_container_name_and_vm_name(self, id):
        host_id, name = self.dispatcher.call_sync(
            'docker.container.query',
            [('id', '=', id)],
            {'single': True, 'select': ('host', 'names.0')}
        )
        host_name = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', host_id)],
            {'single': True, 'select': 'name'}
        )

        return name, host_name

    def get_network_name_and_vm_name(self, id):
        host_id, name = self.dispatcher.call_sync(
            'docker.network.query',
            [('id', '=', id)],
            {'single': True, 'select': ('host', 'name')}
        )
        host_name = self.dispatcher.call_sync(
            'vm.query',
            [('id', '=', host_id)],
            {'single': True, 'select': 'name'}
        )

        return name, host_name


@description('Updates Docker general configuration settings')
@accepts(h.ref('docker-config'))
class DockerUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating Docker global configuration'

    def describe(self, container):
        return TaskDescription('Updating Docker global configuration')

    def verify(self, updated_params):
        return ['docker']

    def run(self, updated_params):
        if 'default_collection' in updated_params:
            if not self.datastore.exists('docker.collections', ('id', '=', updated_params['default_collection'])):
                raise TaskException(
                    errno.ENOENT,
                    'Containers collection {0} does not exist'.format(updated_params['default_collection'])
                )

        node = ConfigNode('container.docker', self.configstore)
        node.update(updated_params)
        state = node.__getstate__()
        if 'api_forwarding' in updated_params:
            try:
                if state['api_forwarding_enable']:
                    self.dispatcher.call_sync('containerd.docker.set_api_forwarding', state['api_forwarding'])
                else:
                    self.dispatcher.call_sync('containerd.docker.set_api_forwarding', None)
            except RpcException as err:
                self.add_warning(
                    TaskWarning(err.code, err.message)
                )


@description('Creates a Docker container')
@accepts(h.all_of(
    h.ref('docker-container'),
    h.required('names', 'image')
))
class DockerContainerCreateTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a Docker container'

    def describe(self, container):
        return TaskDescription('Creating Docker container {name}', name=container['names'][0])

    def verify(self, container):
        host = self.datastore.get_by_id('vms', container.get('host')) or {}
        hostname = host.get('name')

        for v in container.get('volumes', []):
            if v.get('source') and v['source'] != 'HOST' and v['host_path'].startswith('/mnt'):
                raise VerifyException(
                    errno.EINVAL,
                    '{0} is living inside /mnt, but its source is a {1} path'.format(
                        v['host_path'], v['source'].lower()
                    )
                )

        bridge = container.get('bridge')
        if bridge.get('enable') and not (bridge.get('dhcp') or bridge.get('address')):
            raise VerifyException(
                errno.EINVAL,
                'Either dhcp or static address must be selected for bridged container'
            )

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, container):
        if self.datastore.exists('docker.containers', ('names.0', '=', container['names'][0])):
            raise TaskException(errno.EEXIST, 'Docker container {0} already exists'.format(container['names'][0]))

        self.set_progress(0, 'Checking Docker host state')
        normalize(container, {
            'hostname': None,
            'memory_limit': None,
            'volumes': [],
            'ports': [],
            'expose_ports': False,
            'autostart': False,
            'command': [],
            'environment': [],
            'interactive': False,
            'privileged': False,
            'capabilities_add': [],
            'capabilities_drop': [],
            'networks': [],
        })

        for id in container.get('networks'):
            if not self.dispatcher.call_sync('docker.network.query', [('id', '=', id)], {'count': True}):
                raise TaskException(errno.EEXIST, 'Docker network {0} does not exist'.format(id))

        if not container.get('host'):
            container['host'] = self.get_default_host(
                lambda p, m, e=None: self.chunk_progress(0, 30, 'Looking for default Docker host:', p, m, e)
            )

        for v in container.get('volumes', []):
            if v['host_path'].startswith('/mnt'):
                try:
                    ds_id = self.dispatcher.call_sync('volume.decode_path', v['host_path'])[1]
                except RpcException:
                    continue

                ds_perm_type = self.dispatcher.call_sync(
                    'volume.dataset.query',
                    [('id', '=', ds_id)],
                    {'single': True, 'select': 'permissions_type'}
                )
                if str(ds_perm_type) == 'ACL':
                    self.add_warning(TaskWarning(
                        errno.EINVAL,
                        'Dataset\'s {0} Windows type permissions are not supported in container\'s sharing'.format(
                            ds_id
                        )
                    ))

        self.check_host_state(container['host'])

        self.set_progress(30, 'Pulling container {0} image'.format(container['image']))

        image = self.dispatcher.call_sync(
            'docker.image.query',
            [('hosts', 'contains', container['host']), ('names', 'contains', container['image'])],
            {'single': True}
        )

        if not image:
            image = container['image']
            if ':' not in image:
                image += ':latest'

            self.run_subtask_sync(
                'docker.image.pull',
                image,
                container['host'],
                progress_callback=lambda p, m, e=None: self.chunk_progress(
                    30, 90, 'Pulling container {0} image:'.format(image), p, m, e
                )
            )

        container['name'] = container['names'][0]

        self.set_progress(90, 'Creating container {0}'.format(container['name']))

        def match_fn(args):
            if args['operation'] == 'create':
                return self.dispatcher.call_sync(
                    'docker.container.query',
                    [('id', 'in', args['ids']), ('names.0', '=', container['name'])],
                    {'single': True}
                )
            else:
                return False

        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            match_fn,
            lambda: self.dispatcher.call_sync('containerd.docker.create_container', container, timeout=100),
            600
        )

        if container.get('networks'):
            self.set_progress(95, 'Connecting to networks')
            contid = self.dispatcher.call_sync(
                'docker.container.query',
                [('name', '=', container.get('name'))],
                {'select': 'id', 'single': True}
            )
            for netid in container.get('networks'):
                self.run_subtask_sync('docker.network.connect', [contid], netid)

        self.set_progress(100, 'Finished')


@description('Updates a Docker container')
@accepts(str, h.ref('docker-container'))
class DockerContainerUpdateTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating a Docker container'

    def describe(self, id, updated_fields):
        container = self.datastore.get_by_id('docker.containers', id)
        return TaskDescription('Updating Docker container {name}', name=q.get(container, 'names.0', ''))

    def verify(self, id, updated_fields):
        container = self.datastore.get_by_id('docker.containers', id) or {}
        host = self.datastore.get_by_id('vms', container.get('host')) or {}
        hostname = host.get('name')

        for v in updated_fields.get('volumes', []):
            if v.get('source') and v['source'] != 'HOST' and v['host_path'].startswith('/mnt'):
                raise VerifyException(
                    errno.EINVAL,
                    '{0} is living inside /mnt, but its source is a {1} path'.format(
                        v['host_path'], v['source'].lower()
                    )
                )

        bridge = updated_fields.get('bridge', {})
        if bridge.get('enable') and not (bridge.get('dhcp') or bridge.get('address')):
            raise VerifyException(
                errno.EINVAL,
                'Either dhcp or static address must be selected for bridged container'
            )

        if 'running' in updated_fields:
            raise VerifyException(errno.EINVAL, 'Running parameter cannot be set')

        if 'web_ui_url' in updated_fields:
            raise VerifyException(errno.EINVAL, 'Web UI URL cannot be set')

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, id, updated_fields):
        if not self.datastore.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        container = self.dispatcher.call_sync('docker.container.query', [('id', '=', id)], {'single': True})

        container.update(updated_fields)

        self.set_progress(0, 'Deleting old container')
        self.run_subtask_sync(
            'docker.container.delete',
            id,
            progress_callback=lambda p, m, e: self.chunk_progress(0, 50, 'Deleting the old container:', p, m, e)
        )
        self.run_subtask_sync(
            'docker.container.create',
            container,
            progress_callback=lambda p, m, e: self.chunk_progress(50, 100, 'Recreating the container', p, m, e)
        )


@description('Deletes a Docker container')
@accepts(str)
class DockerContainerDeleteTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting a Docker container'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.container.query', [('id', '=', id)], {'single': True, 'select': 'names.0'}
        )
        return TaskDescription('Deleting Docker container {name}', name=name or id)

    def verify(self, id):
        hostname = None
        try:
            hostname = self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', id)
        except RpcException:
            pass

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, id):
        if not self.datastore.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', id)
        except RpcException:
            name, host_name = self.get_container_name_and_vm_name(id)

            self.datastore.delete('docker.containers', id)
            self.dispatcher.dispatch_event('docker.container.changed', {
                'operation': 'delete',
                'ids': [id]
            })

            self.add_warning(TaskWarning(
                errno.EACCES,
                'Cannot access Docker Host {0}. Container {1} was deleted from the local cache only.'.format(
                    host_name or '',
                    name
                )
            ))

            return

        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            lambda args: args['operation'] == 'delete' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.delete_container', id),
            600
        )


@description('Starts a Docker container')
@accepts(str)
class DockerContainerStartTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Starting container'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.container.query', [('id', '=', id)], {'single': True, 'select': 'names.0'}
        )
        return TaskDescription('Starting container {name}', name=name or id)

    def verify(self, id):
        hostname = None
        try:
            hostname = self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', id)
        except RpcException:
            pass

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, id):
        if not self.datastore.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', id)
        except RpcException:
            name, host_name = self.get_container_name_and_vm_name(id)
            raise TaskException(
                errno.EINVAL,
                'Docker Host {0} is currently unreachable. Cannot start {1} container'.format(host_name or '', name)
            )

        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            lambda args: args['operation'] == 'update' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.start', id),
            600
        )


@description('Stops a Docker container')
@accepts(str)
class DockerContainerStopTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Stopping container'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.container.query', [('id', '=', id)], {'single': True, 'select': 'names.0'}
        )
        return TaskDescription('Stopping container {name}', name=name or id)

    def verify(self, id):
        hostname = None
        try:
            hostname = self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', id)
        except RpcException:
            pass

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, id):
        if not self.datastore.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            lambda args: args['operation'] == 'update' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.stop', id),
            600
        )


@description('Clones a Docker container')
@accepts(str, str)
@returns(str)
class DockerContainerCloneTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Cloning a Docker container'

    def describe(self, id, new_name):
        container = self.datastore.get_by_id('docker.containers', id)
        return TaskDescription(
            'Cloning Docker container {name} to {new_name}',
            name=q.get(container, 'names.0', ''),
            new_name=new_name
        )

    def verify(self, id, new_name):
        container = self.datastore.get_by_id('docker.containers', id) or {}
        host = self.datastore.get_by_id('vms', container.get('host')) or {}
        hostname = host.get('name')

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, id, new_name):
        if not self.datastore.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        if self.datastore.exists('docker.containers', ('names.0', '=', new_name)):
            raise TaskException(errno.EEXIST, 'Docker container {0} already exists'.format(new_name))

        container = self.dispatcher.call_sync('docker.container.query', [('id', '=', id)], {'single': True})

        self.set_progress(30, 'Committing a new image {0} from the container {1}'.format(
            new_name,
            q.get(container, 'names.0')
        ))

        image_name = f'freenas/{new_name}:latest'
        cnt = 0
        while self.dispatcher.call_sync('docker.image.query', [('names.0', '=', image_name)], {'count': True}):
            cnt += 1
            image_name = f'freenas/{new_name}_{cnt}:latest'

        image_name = self.run_subtask_sync('docker.container.commit', id, new_name)

        container.pop('id')
        q.set(container, 'names.0', new_name)
        container['image'] = image_name

        return self.run_subtask_sync(
            'docker.container.create',
            container,
            progress_callback=lambda p, m, e: self.chunk_progress(50, 100, '', p, m, e)
        )


@description('Commits a new image from existing Docker container')
@accepts(str, str, h.one_of(str, None))
@returns(str)
class DockerContainerCommitTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Committing a Docker image'

    def describe(self, id, name, tag=None):
        return TaskDescription('Committing the Docker image {name}', name=name)

    def verify(self, id, name, tag=None):
        container = self.datastore.get_by_id('docker.containers', id) or {}
        host = self.datastore.get_by_id('vms', container.get('host')) or {}
        hostname = host.get('name')

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, id, name, tag=None):
        if not self.datastore.exists('docker.containers', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        if self.dispatcher.call_sync('docker.image.query', [('names.0', '=', name)], {'count': True}):
            raise TaskException(errno.EEXIST, 'Docker image {0} already exists'.format(name))

        if not tag:
            tag = 'latest'

        name = f'{name}:{tag}'

        if '/' not in name:
            name = f'freenas/{name}'

        def match_fn(args):
            if args['operation'] == 'create':
                return bool(self.dispatcher.call_sync(
                    'docker.image.query',
                    [('names.0', '=', name)],
                    {'count': True}
                ))
            else:
                return False

        def call_and_get_name():
            nonlocal name
            name = self.dispatcher.call_sync('containerd.docker.commit_image', id, name)

        self.dispatcher.exec_and_wait_for_event(
            'docker.image.changed',
            match_fn,
            call_and_get_name
        )

        return name


@description('Creates a Docker network')
@accepts(h.all_of(
    h.ref('docker-network'),
    h.required('name')
))
class DockerNetworkCreateTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Creating a Docker network'

    def describe(self, network):
        return TaskDescription('Creating Docker network {name}', name=network['name'])

    def verify(self, network):
        if network.get('gateway') and not network.get('subnet'):
            raise TaskException(errno.EINVAL, 'Docker network subnet property is not specified')

        if network.get('subnet') and not network.get('gateway'):
            raise TaskException(errno.EINVAL, 'Docker network gateway property is not specified')

        host = self.datastore.get_by_id('vms', network.get('host')) or {}
        hostname = host.get('name')

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, network):
        if self.datastore.exists('docker.networks', ('name', '=', network['name'])):
            raise TaskException(errno.EEXIST, 'Docker network {0} already exists'.format(network['name']))

        normalize(network, {
            'host': None,
            'driver': 'bridge',
            'subnet': None,
            'gateway': None,
            'containers': []
        })

        for id in network.get('containers'):
            if not self.dispatcher.call_sync('docker.container.query', [('id', '=', id)], {'count': True}):
                raise TaskException(errno.EEXIST, 'Docker container {0} does not exist'.format(id))

        if not network.get('host'):
            network['host'] = self.get_default_host(
                lambda p, m, e=None: self.chunk_progress(0, 30, 'Looking for default Docker host:', p, m, e)
            )

        self.check_host_state(network['host'])

        def match_fn(args):
            if args['operation'] == 'create':
                return self.dispatcher.call_sync(
                    'docker.network.query',
                    [('id', 'in', args['ids']), ('name', '=', network['name'])],
                    {'single': True}
                )
            else:
                return False

        self.dispatcher.exec_and_wait_for_event(
            'docker.network.changed',
            match_fn,
            lambda: self.dispatcher.call_sync('containerd.docker.create_network', network)
        )

        if network.get('containers'):
            netid = self.dispatcher.call_sync(
                'docker.network.query',
                [('name', '=', network.get('name'))],
                {'select': 'id', 'single': True}
            )
            self.run_subtask_sync('docker.network.connect', network.get('containers'), netid)


@description('Deletes a Docker network')
@accepts(str)
class DockerNetworkDeleteTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting a Docker network'

    def describe(self, id):
        name = self.dispatcher.call_sync(
            'docker.network.query', [('id', '=', id)], {'single': True, 'select': 'name'}
        )
        return TaskDescription('Deleting Docker network {name}', name=name or id)

    def verify(self, id):
        hostname = None
        try:
            hostname = self.dispatcher.call_sync('containerd.docker.host_name_by_network_id', id)
        except RpcException:
            pass

        name = self.dispatcher.call_sync('docker.network.query', [('id', '=', id)], {'single': True, 'select': 'name'})
        if name in ('bridge', 'external', 'host', 'none'):
            raise TaskException(errno.EINVAL, 'Cannot delete built-in network "{0}"'.format(name))

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, id):
        name, containers = self.dispatcher.call_sync(
            'docker.network.query',
            [('id', '=', id)],
            {'select': ['name', 'containers'], 'single': True}
        )
        if not name:
            raise TaskException(errno.ENOENT, 'Docker network {0} does not exist'.format(id))

        if containers:
            raise TaskException(errno.EINVAL, 'Cannot delete network "{0}" with connected containers'.format(name))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_network_id', id)
        except RpcException:
            name, host_name = self.get_network_name_and_vm_name(id)

            self.datastore.delete('docker.networks', id)
            self.dispatcher.dispatch_event('docker.network.changed', {
                'operation': 'delete',
                'ids': [id]
            })

            self.add_warning(TaskWarning(
                errno.EACCES,
                'Cannot access Docker Host {0}. Network {1} was deleted from the local cache only.'.format(
                    host_name or '',
                    name
                )
            ))

            return

        self.dispatcher.exec_and_wait_for_event(
            'docker.network.changed',
            lambda args: args['operation'] == 'delete' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.delete_network', id),
            100
        )


@description('Connects selected containers to a network')
@accepts(h.array(str), str)
class DockerNetworkConnectTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Connecting containers to network'

    def describe(self, container_ids, network_id):
        contnames = self.dispatcher.call_sync(
            'docker.container.query', [('id', 'in', container_ids)], {'select': 'name'}
        )
        netname = self.dispatcher.call_sync(
            'docker.network.query', [('id', '=', network_id)], {'single': True, 'select': 'name'}
        )
        return TaskDescription('Connecting containers {contnames} to network {netname}',
                               contnames=','.join(contnames) or ','.join(container_ids),
                               netname=netname or network_id)

    def verify(self, container_ids=None, network_id=None):
        if not container_ids or not network_id:
            raise TaskException(errno.EINVAL, 'Both container(s) and network must be specified')
        hostname = None
        try:
            hostname = self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', container_ids[0])
        except RpcException:
            pass

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, container_ids, network_id):
        for id in container_ids:
            if not self.datastore.exists('docker.containers', ('id', '=', id)):
                raise TaskException(errno.ENOENT, 'Docker container {0} not found'.format(id))

        network = self.dispatcher.call_sync('docker.network.query', [('id', '=', network_id)], {'single': True})
        if not network:
            raise TaskException(errno.ENOENT, 'Docker network {0} does not exist'.format(network['name']))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', container_ids[0])
        except RpcException:
            _, host_name = self.get_container_name_and_vm_name(container_ids[0])
            raise TaskException(
                errno.EINVAL,
                'Docker Host {0} is currently unreachable.'.format(host_name or '')
            )

        for id in container_ids:
            self.dispatcher.exec_and_wait_for_event(
                'docker.container.changed',
                lambda args: args['operation'] == 'update' and id in args['ids'],
                lambda: self.dispatcher.call_sync(
                    'containerd.docker.connect_container_to_network', id, network_id),
                600
            )


@description('Disconnects selected containers from a network')
@accepts(h.array(str), str)
class DockerNetworkDisconnectTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Disconnecting containers from network'

    def describe(self, container_ids, network_id):
        contnames = self.dispatcher.call_sync(
            'docker.container.query', [('id', 'in', container_ids)], {'select': 'name'}
        )
        netname = self.dispatcher.call_sync(
            'docker.network.query', [('id', '=', network_id)], {'single': True, 'select': 'name'}
        )
        return TaskDescription('Disconnecting containers {contnames} from network {netname}',
                               contnames=','.join(contnames) or ','.join(container_ids),
                               netname=netname or network_id)

    def verify(self, container_ids=None, network_id=None):
        if not container_ids or not network_id:
            raise TaskException(errno.EINVAL, 'Both container(s) and network must be specified')
        hostname = None
        try:
            hostname = self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', container_ids[0])
        except RpcException:
            pass

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, container_ids, network_id):
        for id in container_ids:
            if not self.datastore.exists('docker.containers', ('id', '=', id)):
                raise TaskException(errno.ENOENT, 'Docker container {0} does not exist'.format(id))

        network = self.dispatcher.call_sync('docker.network.query', [('id', '=', network_id)], {'single': True})
        if not network:
            raise TaskException(errno.ENOENT, 'Docker network {0} does not exist'.format(network['name']))

        try:
            self.dispatcher.call_sync('containerd.docker.host_name_by_container_id', container_ids[0])
        except RpcException:
            _, host_name = self.get_container_name_and_vm_name(container_ids[0])
            raise TaskException(
                errno.EINVAL,
                'Docker Host {0} is currently unreachable.'.format(host_name or '')
            )

        for cid in container_ids:
            self.dispatcher.exec_and_wait_for_event(
                'docker.container.changed',
                lambda args: args['operation'] == 'update' and cid in args['ids'],
                lambda: self.dispatcher.call_sync(
                    'containerd.docker.disconnect_container_from_network', cid, network_id),
                600
            )


@description('Pulls a selected container image from Docker Hub and caches it on specified Docker host')
@accepts(str, h.one_of(str, None))
class DockerImagePullTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Pulling docker image'

    def describe(self, name, hostid=None):
        return TaskDescription('Pulling docker image {name}', name=name)

    def verify(self, name, hostid=None):
        host = self.datastore.get_by_id('vms', hostid) or {}
        hostname = host.get('name')

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, name, hostid=None):
        if not hostid:
            hostid = self.get_default_host(
                lambda p, m, e=None: self.chunk_progress(0, 10, 'Looking for default Docker host:', p, m, e)
            )

        if ':' not in name:
            name += ':latest'

        if '/' not in name:
            name = 'library/' + name

        hosts = self.dispatcher.call_sync(
            'docker.image.query',
            [('names.0', '=', name)],
            {'select': 'hosts', 'single': True}
        )
        if isinstance(hosts, list):
            hosts.append(hostid)
        else:
            hosts = [hostid]

        hosts = list(set(hosts))

        hosts_progress = {}
        token_rsp = requests.get(
            'https://auth.docker.io/token?service=registry.docker.io&scope=repository:{0}:pull'.format(
                name.split(':')[0]
            )
        )
        if token_rsp.ok:
            manifest = requests.get(
                'https://registry-1.docker.io/v2/{0}/manifests/{1}'.format(*name.split(':', 1)),
                headers={'Authorization': 'Bearer {}'.format(token_rsp.json()['token'])}
            )
            if manifest.ok:
                layers = manifest.json()['fsLayers']
                layers_len = len(layers)
                weight = 1 / (layers_len * len(hosts))
                layers_progress = {l['blobSum'].split(':', 1)[1]: {'Downloading': 0, 'Extracting': 0} for l in layers}
                hosts_progress = {h: copy.deepcopy(layers_progress) for h in hosts}

        @throttle(seconds=1)
        def report_progress(message):
            nonlocal weight
            nonlocal hosts_progress
            progress = 0
            for h in hosts_progress.values():
                for l in h.values():
                    progress += (l['Downloading'] * 0.6 + l['Extracting'] * 0.4) * weight

            progress = 10 + progress * 0.9
            self.set_progress(progress, message)

        for h in hosts:
            try:
                self.check_host_state(h)
            except TaskException:
                continue

            for i in self.dispatcher.call_sync('containerd.docker.pull', name, h, timeout=3600):
                if 'progressDetail' in i and 'current' in i['progressDetail'] and 'total' in i['progressDetail']:
                    if token_rsp.ok and manifest.ok:
                        id = i.get('id', '')
                        status = i.get('status')
                        _, layer = first_or_default(lambda o: o[0].startswith(id), hosts_progress[h].items())
                        if status in ('Downloading', 'Extracting'):
                            layer[status] = i['progressDetail']['current'] / i['progressDetail']['total'] * 100

                        report_progress('{0} layer {1}'.format(i.get('status', ''), i.get('id', '')))
                    else:
                        self.set_progress(None, '{0} layer {1}'.format(i.get('status', ''), i.get('id', '')))


@description('Removes previously cached container image from a Docker host/s')
@accepts(str, h.one_of(str, None))
class DockerImageDeleteTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting docker image'

    def describe(self, id, hostid=None):
        name = self.dispatcher.call_sync('docker.image.query', [('id', '=', id)], {'single': True, 'select': 'names.0'})
        return TaskDescription('Deleting docker image {name}', name=name or '')

    def verify(self, id, hostid=None):
        host = self.datastore.get_by_id('vms', hostid) or {}
        hostname = host.get('name')

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, id, hostid=None):
        name = self.dispatcher.call_sync('docker.image.query', [('id', '=', id)], {'single': True, 'select': 'names.0'})
        if not name:
            raise TaskException(errno.ENOENT, f'Docker container image {id} does not exist')

        if hostid:
            hosts = [hostid]
        else:
            hosts = list(self.dispatcher.call_sync(
                'docker.image.query',
                [('id', '=', id)],
                {'select': 'hosts', 'single': True}
            ))

        related = self.dispatcher.call_sync(
            'docker.container.query',
            [('host', 'in', hosts), ('image_id', '=', id)],
            {'select': ('host', 'names.0')}
        )
        names_in_use = []
        for h, n in related:
            if h in hosts:
                hosts.remove(h)
            names_in_use.append(n)

        if names_in_use:
            self.add_warning(TaskWarning(
                errno.EACCES,
                f'There are containers using {name} image on selected Docker hosts - delete them first: ' +
                ', '.join(names_in_use)
            ))

        def delete_image():
            for h_id in hosts:
                try:
                    self.check_host_state(h_id)
                except TaskException:
                    continue

                try:
                    self.dispatcher.call_sync('containerd.docker.delete_image', id, h_id)
                except RpcException as err:
                    raise TaskException(errno.EACCES, 'Failed to remove image {0}: {1}'.format(name, err))

        def match_fn(args):
            if args['operation'] == 'delete':
                return id in args['ids']
            else:
                return False

        if hosts:
            self.dispatcher.exec_and_wait_for_event(
                'docker.image.changed',
                match_fn,
                lambda: delete_image(),
                600
            )


@description('Removes all previously cached container images')
class DockerImageFlushTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting all docker images'

    def describe(self):
        return TaskDescription('Deleting all docker images')

    def verify(self):
        return ['docker']

    def run(self):
        subtasks = []
        self.set_progress(0, 'Deleting docker images')
        for image in self.dispatcher.call_sync('docker.image.query', [], {'select': 'id'}):
            subtasks.append(self.run_subtask('docker.image.delete', image))

        subtasks_cnt = len(subtasks)
        for idx, t in enumerate(subtasks):
            self.join_subtasks(t)
            self.set_progress(int((idx / subtasks_cnt) * 100), 'Deleting docker images')


@private
@accepts(str, h.ref('vm'))
@description('Updates Docker host resource')
class DockerUpdateHostResourceTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating Docker host resource'

    def describe(self, id, updated_params):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Updating Docker host {name} resource', name=vm.get('name', '') if vm else '')

    def verify(self, id, updated_params):
        return ['docker']

    def run(self, id, updated_params):
        host = self.datastore.query(
            'vms',
            ('config.docker_host', '=', True),
            ('id', '=', id),
            single=True
        )
        resource_name = 'docker:{0}'.format(host['name'])
        self.dispatcher.task_setenv(self.environment['parent'], 'old_name', host['name'])

        if first_or_default(lambda o: o['name'] == resource_name, self.dispatcher.call_sync('task.list_resources')):
            parents = ['docker', 'zpool:{0}'.format(host['target'])]
            self.dispatcher.unregister_resource(resource_name)
            self.dispatcher.register_resource(
                Resource('docker:{0}'.format(updated_params['name'])),
                parents=parents
            )


@private
@accepts(str, h.ref('vm'))
@description('Reverts Docker host resource state')
class DockerRollbackHostResourceTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Reverting Docker host resource state'

    def describe(self, id, updated_params):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Reverting Docker host {name} resource state', name=vm.get('name', '') if vm else '')

    def verify(self, id, updated_params):
        return ['docker']

    def run(self, id, updated_params):
        host = self.datastore.query(
            'vms',
            ('config.docker_host', '=', True),
            ('id', '=', id),
            single=True
        )
        if host:
            old_name = self.environment.get('old_name')
            new_name = updated_params['name']
            parents = ['docker', 'zpool:{0}'.format(host['target'])]
            self.dispatcher.unregister_resource('docker:{0}'.format(new_name))
            self.dispatcher.register_resource(
                Resource('docker:{0}'.format(old_name)),
                parents=parents
            )


@accepts(h.all_of(
    h.ref('docker-collection'),
    h.forbidden('images')
))
@returns(str)
@description('Creates a known Docker cache collection')
class DockerCollectionCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating known collection of containers'

    def describe(self, collection):
        return TaskDescription('Creating known collection of containers {name}', name=collection.get('name', ''))

    def verify(self, collection):
        if 'name' not in collection:
            raise RpcException(errno.EINVAL, 'Collection name has to be specified')
        if 'collection' not in collection:
            raise RpcException(errno.EINVAL, 'Name of Dockerhub collection has to be specified')

        return ['docker']

    def run(self, collection):
        normalize(collection, {
            'match_expr': ''
        })

        if self.datastore.exists('docker.collections', ('name', '=', collection['name'])):
            raise TaskException(errno.EEXIST, 'Containers collection {0} already exists'.format(collection['name']))

        id = self.datastore.insert('docker.collections', collection)
        self.dispatcher.dispatch_event('docker.collection.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@accepts(str, h.all_of(
    h.ref('docker-collection'),
    h.forbidden('images')
))
@description('Updates a known Docker cache collection')
class DockerCollectionUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating known collection of containers'

    def describe(self, id, updated_params):
        collection = self.datastore.get_by_id('docker.collections', id)
        return TaskDescription('Updating known collection of containers {name}', name=collection.get(''))

    def verify(self, id, updated_params):
        return ['docker']

    def run(self, id, updated_params):
        if not self.datastore.exists('docker.collections', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker collection {0} not found'.format(id))
        collection = self.datastore.get_by_id('docker.collections', id)

        collection.update(updated_params)
        if 'name' in updated_params and self.datastore.exists('docker.collections', ('name', '=', collection['name'])):
            raise TaskException(errno.EEXIST, 'Docker collection {0} already exists'.format(collection['name']))

        self.datastore.update('docker.collections', id, collection)
        self.dispatcher.dispatch_event('docker.collection.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
@description('Deletes a known Docker cache collection')
class DockerCollectionDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting known collection of containers'

    def describe(self, id):
        collection = self.datastore.get_by_id('docker.collections', id)
        return TaskDescription('Deleting known collection of containers {name}', name=collection.get(''))

    def verify(self, id):
        return ['docker']

    def run(self, id):
        if not self.datastore.exists('docker.collections', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker collection {0} not found'.format(id))

        self.datastore.delete('docker.collections', id)

        self.dispatcher.dispatch_event('docker.collection.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@accepts(str)
@returns(h.array(h.ref('docker-hub-image')))
@description('Returns a list of Docker images related to a saved collection')
class DockerCollectionGetPresetsTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading Docker collection presets'

    def describe(self, id):
        collection = self.datastore.get_by_id('docker.collections', id)
        return TaskDescription('Downloading Docker collection {name} presets', name=collection.get(''))

    def verify(self, id):
        return ['docker']

    def run(self, id):
        if not self.datastore.exists('docker.collections', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Docker collection {0} not found'.format(id))

        result = []
        collection = self.datastore.get_by_id('docker.collections', id)
        name = collection['collection']

        self.set_progress(0, 'Downloading {0} collection presets'.format(name))

        with dockerhub.DockerHub() as hub:
            collection_len = len([i for i in hub.get_repositories(name) if collection['match_expr'] in i['name']])

        for i in self.dispatcher.call_sync('docker.collection.get_entries', id):
            result.append(i)
            self.set_progress((len(result) / collection_len) * 100, 'Downloading {0} collection presets'.format(name))

        return result


def collect_debug(dispatcher):
    yield AttachData('hosts-query', dumps(list(dispatcher.call_sync('docker.host.query')), indent=4))
    yield AttachData('containers-query', dumps(list(dispatcher.call_sync('docker.container.query')), indent=4))
    yield AttachData('networks-query', dumps(list(dispatcher.call_sync('docker.network.query')), indent=4))
    yield AttachData('images-query', dumps(list(dispatcher.call_sync('docker.image.query')), indent=4))
    yield AttachData('collections-query', dumps(list(dispatcher.call_sync('docker.collection.query')), indent=4))
    yield AttachData('containerd-containers', dumps(list(dispatcher.call_sync(CONTAINERS_QUERY)), indent=4))
    yield AttachData('containerd-networks', dumps(list(dispatcher.call_sync(NETWORKS_QUERY)), indent=4))
    yield AttachData('containerd-images', dumps(list(dispatcher.call_sync(IMAGES_QUERY)), indent=4))


def _depends():
    return ['VMPlugin']


def _init(dispatcher, plugin):
    global collections
    global images
    global containers_state

    containers_lock = RLock()
    networks_lock = RLock()

    images = EventCacheStore(dispatcher, 'docker.image')
    collections = CacheStore()
    containers_state = CacheStore()

    def docker_resource_create_update(name, parents):
        if first_or_default(lambda o: o['name'] == name, dispatcher.call_sync('task.list_resources')):
            dispatcher.update_resource(
                name,
                new_parents=parents
            )
        else:
            dispatcher.register_resource(
                Resource(name),
                parents=parents
            )

    def on_host_event(args):
        if args['operation'] == 'create':
            for host_id in args['ids']:
                refresh_containers(host_id)
                refresh_networks(host_id)

                new_images = list(dispatcher.call_sync(
                    IMAGES_QUERY,
                    [('hosts', 'contains', host_id)], {'select': 'id'}
                ))
                if new_images:
                    sync_images(new_images)

                logger.debug('Docker host {0} started'.format(host_id))

        elif args['operation'] == 'delete':
            for host_id in args['ids']:
                logger.debug('Docker host {0} stopped'.format(host_id))

        dispatcher.dispatch_event('docker.host.changed', {
            'operation': 'update',
            'ids': args['ids']
        })

    def vm_pre_destroy(args):
        host = dispatcher.datastore.query(
            'vms',
            ('config.docker_host', '=', True),
            ('id', '=', args['name']),
            single=True
        )
        if host:
            refresh_containers(args['name'])
            refresh_networks(args['name'])
            logger.debug('Docker host {0} deleted'.format(host['name']))
            dispatcher.unregister_resource('docker:{0}'.format(host['name']))
            dispatcher.dispatch_event('docker.host.changed', {
                'operation': 'delete',
                'ids': [args['name']]
            })

    def on_vm_change(args):
        if args['operation'] == 'create':
            for id in args['ids']:
                host = dispatcher.datastore.query(
                    'vms',
                    ('config.docker_host', '=', True),
                    ('id', '=', id),
                    single=True
                )
                if host:
                    parents = ['docker', 'zpool:{0}'.format(host['target'])]

                    logger.debug('Docker host {0} created'.format(host['name']))
                    docker_resource_create_update('docker:{0}'.format(host['name']), parents)

                    default_host = dispatcher.call_sync('docker.config.get_config').get('default_host')
                    if not default_host:
                        dispatcher.call_task_sync('docker.config.update', {'default_host': host['id']})
                        logger.info('Docker host {0} set automatically as default Docker host'.format(host['name']))

                    dispatcher.dispatch_event('docker.host.changed', {
                        'operation': 'create',
                        'ids': [id]
                    })

        elif args['operation'] == 'delete':
            if dispatcher.call_sync('docker.config.get_config').get('default_host') in args['ids']:
                host = dispatcher.datastore.query(
                    'vms',
                    ('config.docker_host', '=', True),
                    single=True,
                )

                if host:
                    logger.info(
                        'Old default host deleted. Docker host {0} set automatically as default Docker host'.format(
                            host['name']
                        )
                    )
                    host_id = host['id']
                else:
                    logger.info(
                        'Old default host deleted. There are no Docker hosts left to take the role of default host.'
                    )
                    host_id = None

                dispatcher.call_task_sync('docker.config.update', {'default_host': host_id})

        elif args['operation'] == 'update':
            for id in args['ids']:
                host = dispatcher.datastore.query(
                    'vms',
                    ('config.docker_host', '=', True),
                    ('id', '=', id),
                    single=True
                )
                if host:
                    parents = ['docker', 'zpool:{0}'.format(host['target'])]
                    docker_resource_create_update('docker:{0}'.format(host['name']), parents)

                    dispatcher.dispatch_event('docker.host.changed', {
                        'operation': 'update',
                        'ids': [id]
                    })

    def on_image_event(args):
        logger.trace('Received Docker image event: {0}'.format(args))
        if args['ids']:
            if args['operation'] == 'delete':
                images.remove_many(args['ids'])
            else:
                sync_images(args['ids'])

    def on_container_event(args):
        logger.trace('Received Docker container event: {}'.format(args))

        collection = 'docker.containers'
        event = 'docker.container.changed'

        with containers_lock:
            if args['ids']:
                for id in args['ids']:
                    if args['operation'] in ('create', 'update'):
                        state = dispatcher.call_sync(
                            CONTAINERS_QUERY,
                            [('id', '=', id)],
                            {'single': True, 'select': 'running'}
                        )
                        containers_state.put(id, state)
                    else:
                        containers_state.remove(id)

                if args['operation'] == 'delete':
                    for i in args['ids']:
                        dispatcher.datastore.delete(collection, i)

                    dispatcher.dispatch_event(event, {
                        'operation': 'delete',
                        'ids': args['ids']
                    })
                else:
                    objs = dispatcher.call_sync(CONTAINERS_QUERY, [('id', 'in', args['ids'])])
                    for obj in map(lambda o: exclude(o, 'running'), objs):
                        if args['operation'] == 'create':
                            dispatcher.datastore.insert(collection, obj)
                        else:
                            dispatcher.datastore.update(collection, obj['id'], obj)

                        dispatcher.dispatch_event(event, {
                            'operation': args['operation'],
                            'ids': args['ids']
                        })

    def on_network_event(args):
        logger.trace('Received Docker network event: {}'.format(args))

        collection = 'docker.networks'
        event = 'docker.network.changed'

        with networks_lock:
            if args['ids']:
                if args['operation'] == 'delete':
                    for i in args['ids']:
                        dispatcher.datastore.delete(collection, i)

                    dispatcher.dispatch_event(event, {
                        'operation': 'delete',
                        'ids': args['ids']
                    })
                else:
                    objs = dispatcher.call_sync(NETWORKS_QUERY, [('id', 'in', args['ids'])])
                    for obj in objs:
                        if args['operation'] == 'create':
                            dispatcher.datastore.insert(collection, obj)
                        else:
                            dispatcher.datastore.update(collection, obj['id'], obj)

                        dispatcher.dispatch_event(event, {
                            'operation': args['operation'],
                            'ids': args['ids']
                        })

    def on_collection_change(args):
        if args['operation'] == 'delete':
            node = ConfigNode('container.docker', dispatcher.configstore)
            default_collection = node.__getstate__().get('default_collection')
            if default_collection and default_collection in args['ids']:
                node.update({'default_collection': None})

    def refresh_database_cache(collection, event, query, host_id=None):
        filter = []
        if host_id:
            filter.append(('host', '=', host_id))
        else:
            active_hosts = list(dispatcher.call_sync('docker.host.query', [('state', '=', 'UP')], {'select': 'id'}))
            filter.append(('host', 'in', active_hosts))

        with containers_lock:
            current = list(dispatcher.call_sync(query, filter))
            old = dispatcher.datastore.query(collection, *filter)
            created = []
            updated = []
            deleted = []
            for obj in map(lambda o: exclude(o, 'running'), current):
                old_obj = first_or_default(lambda o: o['id'] == obj['id'], old)
                if old_obj:
                    if obj != old_obj:
                        dispatcher.datastore.update(collection, obj['id'], obj)
                        updated.append(obj['id'])

                else:
                    dispatcher.datastore.insert(collection, obj)
                    created.append(obj['id'])

            for obj in old:
                if not first_or_default(lambda o: o['id'] == obj['id'], current):
                    dispatcher.datastore.delete(collection, obj['id'])
                    deleted.append(obj['id'])

            if created:
                dispatcher.dispatch_event(event, {
                    'operation': 'create',
                    'ids': created
                })

            if updated:
                dispatcher.dispatch_event(event, {
                    'operation': 'update',
                    'ids': updated
                })

            if deleted:
                dispatcher.dispatch_event(event, {
                    'operation': 'delete',
                    'ids': deleted
                })

    def refresh_networks(host_id=None):
        refresh_database_cache('docker.networks', 'docker.network.changed', NETWORKS_QUERY, host_id)

    def refresh_containers(host_id=None):
        refresh_database_cache('docker.containers', 'docker.container.changed', CONTAINERS_QUERY, host_id)

    def sync_images(ids=None, host_id=None):
        filter = []
        if ids:
            filter.append(('id', 'in', ids))

        if host_id:
            filter.append(('hosts', 'contains', host_id))

        objects = list(dispatcher.call_sync(IMAGES_QUERY, filter))
        images.update(**{i['id']: i for i in objects})
        if not ids:
            nonexistent_ids = []
            for k, v in images.itervalid():
                if not first_or_default(lambda o: o['id'] == k, objects):
                    nonexistent_ids.append(k)

            images.remove_many(nonexistent_ids)

    def refresh_cache(host_id=None):
        logger.trace('Syncing Docker containers, networks, image cache')

        sync_images(host_id=host_id)
        refresh_containers(host_id=host_id)
        refresh_networks(host_id=host_id)

        if not images.ready:
            logger.trace('Docker images cache initialized')
            images.ready = True

    plugin.register_provider('docker.config', DockerConfigProvider)
    plugin.register_provider('docker.host', DockerHostProvider)
    plugin.register_provider('docker.container', DockerContainerProvider)
    plugin.register_provider('docker.network', DockerNetworkProvider)
    plugin.register_provider('docker.image', DockerImagesProvider)
    plugin.register_provider('docker.collection', DockerCollectionProvider)

    plugin.register_task_handler('docker.config.update', DockerUpdateTask)

    plugin.register_task_handler('docker.container.create', DockerContainerCreateTask)
    plugin.register_task_handler('docker.container.update', DockerContainerUpdateTask)
    plugin.register_task_handler('docker.container.delete', DockerContainerDeleteTask)
    plugin.register_task_handler('docker.container.start', DockerContainerStartTask)
    plugin.register_task_handler('docker.container.stop', DockerContainerStopTask)
    plugin.register_task_handler('docker.container.clone', DockerContainerCloneTask)
    plugin.register_task_handler('docker.container.commit', DockerContainerCommitTask)

    plugin.register_task_handler('docker.network.create', DockerNetworkCreateTask)
    plugin.register_task_handler('docker.network.delete', DockerNetworkDeleteTask)
    plugin.register_task_handler('docker.network.connect', DockerNetworkConnectTask)
    plugin.register_task_handler('docker.network.disconnect', DockerNetworkDisconnectTask)

    plugin.register_task_handler('docker.image.pull', DockerImagePullTask)
    plugin.register_task_handler('docker.image.delete', DockerImageDeleteTask)
    plugin.register_task_handler('docker.image.flush', DockerImageFlushTask)

    plugin.register_task_handler('docker.host.update_resource', DockerUpdateHostResourceTask)
    plugin.register_task_handler('docker.host.rollback_resource', DockerRollbackHostResourceTask)

    plugin.register_task_handler('docker.collection.create', DockerCollectionCreateTask)
    plugin.register_task_handler('docker.collection.update', DockerCollectionUpdateTask)
    plugin.register_task_handler('docker.collection.delete', DockerCollectionDeleteTask)
    plugin.register_task_handler('docker.collection.get_presets', DockerCollectionGetPresetsTask)

    plugin.register_event_type('docker.host.changed')
    plugin.register_event_type('docker.container.changed')
    plugin.register_event_type('docker.network.changed')
    plugin.register_event_type('docker.image.changed')
    plugin.register_event_type('docker.collection.changed')

    plugin.register_event_handler('containerd.docker.host.changed', on_host_event)
    plugin.register_event_handler('containerd.docker.container.changed', on_container_event)
    plugin.register_event_handler('containerd.docker.network.changed', on_network_event)
    plugin.register_event_handler('containerd.docker.image.changed', on_image_event)
    plugin.register_event_handler('containerd.docker.client.disconnected', lambda a: refresh_cache(host_id=a['id']))
    plugin.register_event_handler('vm.changed', on_vm_change)
    plugin.register_event_handler('plugin.service_registered',
                                  lambda a: refresh_cache() if a['service-name'] == 'containerd.docker' else None)
    plugin.register_event_handler('docker.collection.changed', on_collection_change)

    plugin.attach_hook('vm.pre_destroy', vm_pre_destroy)

    dispatcher.register_resource(Resource('docker'))

    plugin.register_debug_hook(collect_debug)

    def resource_hook_condition(id, updated_params):
        return 'name' in updated_params

    dispatcher.register_task_hook(
        'vm.update:before',
        'docker.host.update_resource',
        resource_hook_condition
    )
    dispatcher.register_task_hook(
        'vm.update:error',
        'docker.host.rollback_resource',
        resource_hook_condition
    )

    plugin.register_schema_definition('docker-config', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'default_host': {'type': ['string', 'null']},
            'api_forwarding': {'type': ['string', 'null']},
            'default_collection': {'type': ['string', 'null']},
            'api_forwarding_enable': {'type': 'boolean'}
        }
    })

    plugin.register_schema_definition('docker-collection', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'collection': {'type': 'string'},
            'match_expr': {'type': ['string', 'null']},
            'images': {'$ref': 'docker-hub-image'}
        }
    })

    plugin.register_schema_definition('docker-host', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'state': {'$ref': 'docker-host-state'},
            'status': {
                'oneOf': [{'$ref': 'docker-host-status'}, {'type': 'null'}]
            }
        }
    })

    plugin.register_schema_definition('docker-host-state', {
        'type': 'string',
        'enum': ['UP', 'DOWN']
    })

    plugin.register_schema_definition('docker-host-status', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'unique_id': {'type': 'string'},
            'hostname': {'type': 'string'},
            'os': {'type': 'string'},
            'mem_total': {'type': 'integer'}
        }
    })

    plugin.register_schema_definition('docker-container', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'names': {
                'type': 'array',
                'items': {
                    'type': 'string',
                    'pattern': docker_names_pattern
                }
            },
            'command': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'image': {'type': 'string'},
            'image_id': {'type': 'string'},
            'host': {'type': ['string', 'null']},
            'hostname': {'type': ['string', 'null']},
            'memory_limit': {'type': ['integer', 'null']},
            'expose_ports': {'type': 'boolean'},
            'autostart': {'type': 'boolean'},
            'running': {'type': 'boolean'},
            'reachable': {'type': 'boolean'},
            'interactive': {'type': 'boolean'},
            'version': {'type': 'string'},
            'web_ui_url': {'type': 'string'},
            'hub_url': {'type': 'string'},
            'environment': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'exec_ids': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'settings': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'id': {'type': 'string'},
                        'value': {'type': ['string', 'integer', 'boolean', 'null']}
                    }
                }
            },
            'ports': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'protocol': {'$ref': 'docker-port-protocol'},
                        'container_port': {
                            'type': 'integer',
                            'minimum': 0,
                            'maximum': 65535
                        },
                        'host_port': {
                            'type': 'integer',
                            'minimum': 0,
                            'maximum': 65535
                        }
                    }
                }
            },
            'volumes': {
                'type': 'array',
                'items': {'$ref': 'docker-volume'}
            },
            'bridge': {'$ref': 'docker-container-bridge'},
            'parent_directory': {'type': 'string'},
            'capabilities_add': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'capabilities_drop': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'privileged': {'type': 'boolean'},
            'networks': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('docker-container-bridge', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'enable': {'type': 'boolean'},
            'dhcp': {'type': 'boolean'},
            'address': {'type': ['string', 'null']},
            'macaddress': {'type': ['string', 'null']}
        }
    })

    plugin.register_schema_definition('docker-network', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {
                'type': 'string',
                'pattern': docker_names_pattern
            },
            'host': {'type': ['string', 'null']},
            'driver': {'type': ['string', 'null']},
            'subnet': {'type': ['string', 'null']},
            'gateway': {'type': ['string', 'null']},
            'containers': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('docker-image', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'names': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'size': {'type': 'integer'},
            'hosts': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'presets': {'type': ['object', 'null']},
            'version': {'type': 'string'},
            'created_at': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('docker-hub-image', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'icon': {'type': 'string'},
            'pull_count': {'type': 'integer'},
            'star_count': {'type': 'integer'},
            'version': {'type': 'string'},
            'presets': {'type': ['object', 'null']}
        }
    })

    plugin.register_schema_definition('docker-volume', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'container_path': {'type': 'string'},
            'host_path': {'type': 'string'},
            'readonly': {'type': 'boolean'},
            'source': {'$ref': 'docker-volume-host-path-source'}
        }
    })

    plugin.register_schema_definition('docker-port-protocol', {
        'type': 'string',
        'enum': ['TCP', 'UDP']
    })

    plugin.register_schema_definition('docker-volume-host-path-source', {
        'type': 'string',
        'enum': ['HOST', 'VM']
    })

    if 'containerd.docker' in dispatcher.call_sync('discovery.get_services'):
        refresh_cache()

    if not dispatcher.call_sync('docker.config.get_config').get('default_host'):
        host_id = dispatcher.datastore.query(
            'vms',
            ('config.docker_host', '=', True),
            single=True,
            select='id'
        )
        if host_id:
            dispatcher.call_task_sync('docker.config.update', {'default_host': host_id})

    for h in dispatcher.datastore.query_stream('vms', ('config.docker_host', '=', True)):
        parents = ['docker', 'zpool:{0}'.format(h['target'])]
        dispatcher.register_resource(
            Resource('docker:{0}'.format(h['name'])),
            parents=parents
        )

