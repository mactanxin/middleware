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

import re
import copy
import errno
import gevent
import dockerfile_parse
import dockerhub
import socket
import logging
import requests
from gevent.lock import RLock
from resources import Resource
from datetime import datetime, timedelta
from task import Provider, Task, ProgressTask, TaskDescription, TaskException, query, TaskWarning, VerifyException
from cache import EventCacheStore, CacheStore
from datastore.config import ConfigNode
from freenas.utils import normalize, query as q, first_or_default
from freenas.utils.decorators import throttle
from freenas.dispatcher.rpc import generator, accepts, returns, SchemaHelper as h, RpcException, description, private
from freenas.dispatcher.jsonenc import loads, dumps
from debug import AttachData

logger = logging.getLogger(__name__)
containers = None
images = None
collections = None

CONTAINERS_QUERY = 'containerd.docker.query_containers'
IMAGES_QUERY = 'containerd.docker.query_images'

dockerfile_parser_logger = logging.getLogger('dockerfile_parse.parser')
dockerfile_parser_logger.setLevel(logging.ERROR)


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
            results = self.datastore.query('vms', ('config.docker_host', '=', True), callback=extend)
        return q.query(results, *(filter or []), stream=True, **(params or {}))


@description('Provides information about Docker containers')
class DockerContainerProvider(Provider):
    @description('Returns current status of Docker containers')
    @query('docker-container')
    @generator
    def query(self, filter=None, params=None):
        def find_env(env, name):
            for i in env:
                n, v = i.split('=', maxsplit=1)
                if n == name:
                    return v

            return None

        def extend(obj):
            presets = self.dispatcher.call_sync('docker.image.labels_to_presets', obj['labels'])
            settings = obj.setdefault('settings', [])
            address = q.get(obj, 'bridge.address') or socket.gethostname()
            obj.update({
                'web_ui_url': None,
                'settings': [],
                'version': '0'
            })

            if presets:
                for i in presets.get('settings', []):
                    settings.append({
                        'id': i['id'],
                        'value': find_env(obj['environment'], i['id'])
                    })

                if presets.get('web_ui_protocol'):
                    obj['web_ui_url'] = '{0}://{1}:{2}/{3}'.format(
                        presets['web_ui_protocol'],
                        address,
                        presets['web_ui_port'],
                        presets['web_ui_path'][1:]
                    )

                obj['version'] = presets.get('version', '0')

            return obj

        return containers.query(*(filter or []), stream=True, callback=extend, **(params or {}))

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
        def extend(obj):
            obj['presets'] = self.labels_to_presets(obj['labels'])
            obj['version'] = '0' if not obj['presets'] else obj['presets'].get('version', '0')
            return obj

        return images.query(*(filter or []), stream=True, callback=extend, **(params or {}))

    @description('Returns a result of searching Docker Hub for a specified term - part of image name')
    @accepts(str)
    @returns(h.array(h.ref('docker-hub-image')))
    @generator
    def search(self, term):
        parser = dockerfile_parse.DockerfileParser()
        hub = dockerhub.DockerHub()

        for i in hub.search(term):
            presets = None
            icon = None

            if i['is_automated']:
                # Fetch dockerfile
                try:
                    parser.content = hub.get_dockerfile(i['repo_name'])
                    presets = self.labels_to_presets(parser.labels)
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
        def update_collection(c):
            parser = dockerfile_parse.DockerfileParser()
            hub = dockerhub.DockerHub()
            items = []

            with self.update_collection_lock:
                for i in hub.get_repositories(c):
                    presets = None
                    icon = None
                    repo_name = '{0}/{1}'.format(i['user'], i['name'])

                    if i['is_automated']:
                        # Fetch dockerfile
                        try:
                            parser.content = hub.get_dockerfile(repo_name)
                            presets = self.labels_to_presets(parser.labels)
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

        if collections.is_valid(collection):
            collection_data = collections.get(collection)
            time_since_last_update = now - collection_data['update_time']

            if time_since_last_update > self.throttle_period:
                update_collection(collection)
        else:
            update_collection(collection)

        collection_data = collections.get(collection)
        for i in collection_data['items']:
            yield i

    @description('Returns a full description of specified Docker container image')
    @accepts(str)
    @returns(str)
    def readme(self, repo_name):
        hub = dockerhub.DockerHub()
        try:
            return hub.get_repository(repo_name).get('full_description')
        except ValueError:
            return None

    def labels_to_presets(self, labels):
        if not labels:
            return None

        result = {
            'interactive': labels.get('org.freenas.interactive', 'false') == 'true',
            'upgradeable': labels.get('org.freenas.upgradeable', 'false') == 'true',
            'expose_ports': labels.get('org.freenas.expose-ports-at-host', 'false') == 'true',
            'web_ui_protocol': labels.get('org.freenas.web-ui-protocol'),
            'web_ui_port': labels.get('org.freenas.web-ui-port'),
            'web_ui_path': labels.get('org.freenas.web-ui-path'),
            'version': labels.get('org.freenas.version'),
            'bridge': {
                'enable': labels.get('org.freenas.bridged') == 'true',
                'address': None
            },
            'ports': [],
            'volumes': [],
            'static_volumes': [],
            'settings': []
        }

        if 'org.freenas.port-mappings' in labels:
            for mapping in labels['org.freenas.port-mappings'].split(','):
                m = re.match(r'^(\d+):(\d+)/(tcp|udp)$', mapping)
                if not m:
                    continue

                result['ports'].append({
                    'container_port': int(m.group(1)),
                    'host_port': int(m.group(2)),
                    'protocol': m.group(3).upper()
                })

        if 'org.freenas.volumes' in labels:
            try:
                j = loads(labels['org.freenas.volumes'])
            except ValueError:
                pass
            else:
                for vol in j:
                    if 'name' not in vol:
                        continue

                    result['volumes'].append({
                        'description': vol.get('descr'),
                        'container_path': vol['name'],
                        'readonly': vol.get('readonly', False)
                    })

        if 'org.freenas.static_volumes' in labels:
            try:
                j = loads(labels['org.freenas.static_volumes'])
            except ValueError:
                pass
            else:
                for vol in j:
                    if any(v not in vol for v in ('container_path', 'host_path')):
                        continue

                    result['volumes'].append(vol)

        if 'org.freenas.settings' in labels:
            try:
                j = loads(labels['org.freenas.settings'])
            except ValueError:
                pass
            else:
                for setting in j:
                    if 'env' not in setting:
                        continue

                    result['settings'].append({
                        'id': setting['env'],
                        'description': setting.get('descr'),
                        'optional': setting.get('optional', True)
                    })

        return result


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

        for i in self.dispatcher.call_sync('docker.image.get_collection_images', collection['collection']):
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
                self.join_subtasks(self.run_subtask('docker.config.update', {'default_host': hostid}))
                return hostid

            host_name = 'docker_host_' + str(self.dispatcher.call_sync(
                'vm.query', [('name', '~', 'docker_host_')], {'count': True}
            ))

            biggest_volume = self.dispatcher.call_sync(
                'volume.query',
                [('status', '=', 'ONLINE')],
                {'sort': ['properties.size.parsed'], 'single': True, 'select': 'id'}
            )
            if not biggest_volume:
                raise TaskException(
                    errno.ENOENT,
                    'There are no healthy online pools available. Docker host could not be created.'
                )

            self.join_subtasks(self.run_subtask(
                'vm.create', {
                    'name': host_name,
                    'template': {'name': 'boot2docker'},
                    'target': biggest_volume
                },
                progress_callback=progress_cb
            ))

            hostid = self.dispatcher.call_sync(
                'vm.query',
                [('name', '=', host_name)],
                {'single': True, 'select': 'id'}
            )

            self.join_subtasks(self.run_subtask('vm.start', hostid))

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

        if host['state'] == 'DOWN':
            raise TaskException(errno.EHOSTDOWN, 'Docker host {0} is down'.format(host['name']))


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
        if not container.get('names'):
            raise VerifyException(errno.EINVAL, 'Container name must be specified')
        else:
            if not re.match(r'[a-zA-Z0-9.-]*$', container['names'][0]):
                raise VerifyException(
                    errno.EINVAL,
                    'Invalid container name: {0}. Only [a-zA-Z0-9.-] characters are allowed'.format(
                        container['names'][0]
                    )
                )

        if not container.get('image'):
            raise VerifyException(errno.EINVAL, 'Image name must be specified')

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

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, container):
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
            'interactive': False
        })

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

            self.join_subtasks(self.run_subtask(
                'docker.image.pull',
                image,
                container['host'],
                progress_callback=lambda p, m, e=None: self.chunk_progress(
                    30, 90, 'Pulling container {0} image:'.format(image), p, m, e
                )
            ))

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
            lambda: self.dispatcher.call_sync('containerd.docker.create', container),
            600
        )
        self.set_progress(100, 'Finished')


@description('Deletes a Docker container')
@accepts(str)
class DockerContainerDeleteTask(ProgressTask):
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
        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            lambda args: args['operation'] == 'delete' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.delete', id),
            600
        )


@description('Starts a Docker container')
@accepts(str)
class DockerContainerStartTask(Task):
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
        self.dispatcher.exec_and_wait_for_event(
            'docker.container.changed',
            lambda args: args['operation'] == 'update' and id in args['ids'],
            lambda: self.dispatcher.call_sync('containerd.docker.stop', id),
            600
        )


@description('Pulls a selected container image from Docker Hub and caches it on specified Docker host')
@accepts(str, h.one_of(str, None))
class DockerImagePullTask(DockerBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Pulling docker image'

    def describe(self, name, hostid):
        return TaskDescription('Pulling docker image {name}', name=name)

    def verify(self, name, hostid):
        host = self.datastore.get_by_id('vms', hostid) or {}
        hostname = host.get('name')

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, name, hostid):
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
            self.check_host_state(h)

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

    def describe(self, name, hostid=None):
        return TaskDescription('Deleting docker image {name}', name=name)

    def verify(self, name, hostid=None):
        host = self.datastore.get_by_id('vms', hostid) or {}
        hostname = host.get('name')

        if hostname:
            return ['docker:{0}'.format(hostname)]
        else:
            return ['docker']

    def run(self, name, hostid=None):
        if hostid:
            hosts = [hostid]
        else:
            hosts = self.dispatcher.call_sync(
                'docker.image.query',
                [('names.0', '=', name)],
                {'select': 'hosts', 'single': True}
            )

        def delete_image():
            for id in hosts:
                self.check_host_state(id)
                try:
                    self.dispatcher.call_sync('containerd.docker.delete_image', name, id)
                except RpcException as err:
                    raise TaskException(errno.EACCES, 'Failed to remove image {0}: {1}'.format(name, err))

        def match_fn(args):
            if args['operation'] == 'delete':
                return not self.dispatcher.call_sync(
                    'docker.image.query',
                    [('names', 'contains', name)],
                    {'single': True}
                )
            else:
                return False

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
        for image in self.dispatcher.call_sync('docker.image.query', [], {'select': 'names.0'}):
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
            raise RpcException(errno.EINVAL, 'Name of DockerHub collection has to be specified')

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


def collect_debug(dispatcher):
    yield AttachData('hosts-query', dumps(list(dispatcher.call_sync('docker.host.query')), indent=4))
    yield AttachData('containers-query', dumps(list(dispatcher.call_sync('docker.container.query')), indent=4))
    yield AttachData('images-query', dumps(list(dispatcher.call_sync('docker.image.query')), indent=4))
    yield AttachData('collections-query', dumps(list(dispatcher.call_sync('docker.collection.query')), indent=4))
    yield AttachData('containerd-containers', dumps(list(dispatcher.call_sync(CONTAINERS_QUERY)), indent=4))
    yield AttachData('containerd-images', dumps(list(dispatcher.call_sync(IMAGES_QUERY)), indent=4))


def _depends():
    return ['VMPlugin']


def _init(dispatcher, plugin):
    global containers
    global images
    global collections

    containers = EventCacheStore(dispatcher, 'docker.container')
    images = EventCacheStore(dispatcher, 'docker.image')
    collections = CacheStore()

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
        if images.ready and containers.ready:
            if args['operation'] == 'create':
                for host_id in args['ids']:
                    new_images = list(dispatcher.call_sync(
                        IMAGES_QUERY,
                        [('hosts', 'contains', host_id)], {'select': 'id'}
                    ))
                    new_containers = list(dispatcher.call_sync(
                        CONTAINERS_QUERY,
                        [('host', '=', host_id)], {'select': 'id'}
                    ))

                    if new_images:
                        sync_cache(images, IMAGES_QUERY, new_images)
                    if new_containers:
                        sync_cache(containers, CONTAINERS_QUERY, new_containers)

                    logger.debug('Docker host {0} started'.format(host_id))

            elif args['operation'] == 'delete':
                sync_cache(images, IMAGES_QUERY)
                for host_id in args['ids']:
                    containers.remove_many(containers.query(('host', '=', host_id), select='id'))

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
                        'ids': id
                    })

    def on_image_event(args):
        logger.trace('Received Docker image event: {0}'.format(args))
        if args['ids']:
            if args['operation'] == 'delete':
                images.remove_many(args['ids'])
            else:
                sync_cache(images, IMAGES_QUERY, args['ids'])

    def on_container_event(args):
        logger.trace('Received Docker container event: {0}'.format(args))
        if args['ids']:
            if args['operation'] == 'delete':
                containers.remove_many(args['ids'])
            else:
                sync_cache(containers, CONTAINERS_QUERY, args['ids'])

    def on_collection_change(args):
        if args['operation'] == 'delete':
            node = ConfigNode('container.docker', dispatcher.configstore)
            default_collection = node.__getstate__().get('default_collection')
            if default_collection and default_collection in args['ids']:
                node.update({'default_collection': None})

    def sync_caches():
        interval = dispatcher.configstore.get('container.cache_refresh_interval')
        while True:
            gevent.sleep(interval)
            if images.ready and containers.ready:
                logger.trace('Syncing Docker caches')
                try:
                    sync_cache(images, IMAGES_QUERY)
                    sync_cache(containers, CONTAINERS_QUERY)
                except RpcException:
                    pass

    def sync_cache(cache, query, ids=None):
        objects = list(dispatcher.call_sync(query, [('id', 'in', ids)] if ids else []))
        cache.update(**{i['id']: i for i in objects})
        if not ids:
            nonexistent_ids = []
            for k, v in cache.itervalid():
                if not first_or_default(lambda o: o['id'] == k, objects):
                    nonexistent_ids.append(k)

            cache.remove_many(nonexistent_ids)

    def init_cache():
        logger.trace('Initializing Docker caches')
        sync_cache(images, IMAGES_QUERY)
        images.ready = True
        sync_cache(containers, CONTAINERS_QUERY)
        containers.ready = True

    plugin.register_provider('docker.config', DockerConfigProvider)
    plugin.register_provider('docker.host', DockerHostProvider)
    plugin.register_provider('docker.container', DockerContainerProvider)
    plugin.register_provider('docker.image', DockerImagesProvider)
    plugin.register_provider('docker.collection', DockerCollectionProvider)

    plugin.register_task_handler('docker.config.update', DockerUpdateTask)

    plugin.register_task_handler('docker.container.create', DockerContainerCreateTask)
    plugin.register_task_handler('docker.container.delete', DockerContainerDeleteTask)
    plugin.register_task_handler('docker.container.start', DockerContainerStartTask)
    plugin.register_task_handler('docker.container.stop', DockerContainerStopTask)

    plugin.register_task_handler('docker.image.pull', DockerImagePullTask)
    plugin.register_task_handler('docker.image.delete', DockerImageDeleteTask)
    plugin.register_task_handler('docker.image.flush', DockerImageFlushTask)

    plugin.register_task_handler('docker.host.update_resource', DockerUpdateHostResourceTask)
    plugin.register_task_handler('docker.host.rollback_resource', DockerRollbackHostResourceTask)

    plugin.register_task_handler('docker.collection.create', DockerCollectionCreateTask)
    plugin.register_task_handler('docker.collection.update', DockerCollectionUpdateTask)
    plugin.register_task_handler('docker.collection.delete', DockerCollectionDeleteTask)

    plugin.register_event_type('docker.host.changed')
    plugin.register_event_type('docker.container.changed')
    plugin.register_event_type('docker.image.changed')
    plugin.register_event_type('docker.collection.changed')

    plugin.register_event_handler('containerd.docker.host.changed', on_host_event)
    plugin.register_event_handler('containerd.docker.container.changed', on_container_event)
    plugin.register_event_handler('containerd.docker.image.changed', on_image_event)
    plugin.register_event_handler('vm.changed', on_vm_change)
    plugin.register_event_handler('plugin.service_registered',
                                  lambda a: init_cache() if a['service-name'] == 'containerd.docker' else None)
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
                'items': {'type': 'string'}
            },
            'command': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'image': {'type': 'string'},
            'host': {'type': ['string', 'null']},
            'hostname': {'type': ['string', 'null']},
            'status': {'type': ['string', 'null']},
            'memory_limit': {'type': ['integer', 'null']},
            'expose_ports': {'type': 'boolean'},
            'autostart': {'type': 'boolean'},
            'running': {'type': 'boolean'},
            'interactive': {'type': 'boolean'},
            'version': {'type': 'string'},
            'web_ui_url': {'type': 'string'},
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
            'parent_directory': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('docker-container-bridge', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'enable': {'type': 'boolean'},
            'address': {'type': ['string', 'null']}
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
        init_cache()

    if not dispatcher.call_sync('docker.config.get_config').get('default_host'):
        host_id = dispatcher.datastore.query(
            'vms',
            ('config.docker_host', '=', True),
            single=True,
            select='id'
        )
        if host_id:
            dispatcher.call_task_sync('docker.config.update', {'default_host': host_id})

    gevent.spawn(sync_caches)

    for h in dispatcher.datastore.query('vms', ('config.docker_host', '=', True)):
        parents = ['docker', 'zpool:{0}'.format(h['target'])]
        dispatcher.register_resource(
            Resource('docker:{0}'.format(h['name'])),
            parents=parents
        )

