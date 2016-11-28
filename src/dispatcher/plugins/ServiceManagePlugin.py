#+
# Copyright 2014 iXsystems, Inc.
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

import os
import errno
import gevent
import gevent.pool
import logging

from task import Task, Provider, TaskException, TaskDescription, ValidationException, query
from debug import AttachFile, AttachCommandOutput
from resources import Resource
from freenas.dispatcher.rpc import RpcException, description, accepts, private, returns, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from datastore.config import ConfigNode
from lib.system import system, SubprocessException
from freenas.utils import extend as extend_dict, query as q


logger = logging.getLogger('ServiceManagePlugin')


@description("Provides info about available services and their state")
class ServiceInfoProvider(Provider):
    @description("Lists available services")
    @query("service")
    @generator
    def query(self, filter=None, params=None):
        def extend(i):
            state, pid = get_status(self.dispatcher, self.datastore, i)
            entry = {
                'id': i['id'],
                'name': i['name'],
                'state': state,
            }

            if pid is not None:
                entry['pid'] = pid

            entry['builtin'] = i['builtin']
            return entry

        # Running extend sequentially might take too long due to the number of services
        # and `service ${name} onestatus`. To workaround that run it in parallel using gevent
        result = self.datastore.query('service_definitions', *(filter or []))
        if result is None:
            return result
        jobs = {
            gevent.spawn(extend, entry): entry
            for entry in result
        }
        gevent.joinall(list(jobs.keys()), timeout=15)
        group = gevent.pool.Group()

        def result(greenlet):
            if greenlet.value is None:
                entry = jobs.get(greenlet)
                return {
                    'name': entry['name'],
                    'state': 'UNKNOWN',
                    'builtin': entry['builtin'],
                }
            else:
                return greenlet.value

        result = group.map(result, jobs)
        result = list(map(lambda s: extend_dict(s, {'config': self.get_service_config(s['id'])}), result))
        return q.query(result, *(filter or []), stream=True, **(params or {}))

    @accepts(str)
    @returns(h.object())
    def get_service_config(self, id):
        svc = self.datastore.get_by_id('service_definitions', id)
        if not svc:
            raise RpcException(errno.EINVAL, 'Invalid service name')

        if svc.get('get_config_rpc'):
            ret = self.dispatcher.call_sync(svc['get_config_rpc'])
        else:
            ret = ConfigNode('service.{0}'.format(svc['name']), self.configstore).__getstate__()

        if not ret:
            return

        return extend_dict(ret, {
            'type': 'service-{0}'.format(svc['name'])
        })

    @private
    @accepts(str)
    def ensure_started(self, service):
        # XXX launchd!
        svc = self.datastore.get_one('service_definitions', ('name', '=', service))
        if not svc:
            raise RpcException(errno.ENOENT, 'Service {0} not found'.format(service))

        if 'rcng' not in svc:
            if 'start_rpc' in svc:
                try:
                    self.dispatcher.call_sync(svc['start_rpc'])
                    return True
                except RpcException:
                    raise RpcException(
                        errno.ENOENT,
                        "Whilst starting service {0} rpc '{1}' failed".format(service, svc['start_rpc'])
                    )
            else:
                return

        rc_scripts = svc['rcng']['rc-scripts']

        if type(rc_scripts) is str:
            try:
                system("/usr/sbin/service", rc_scripts, 'onestart')
            except SubprocessException as e:
                raise RpcException(
                    errno.ENOENT,
                    "Whilst starting service {0} command 'service {1} onestart'".format(service, rc_scripts) +
                    " failed with error: {0}".format(e.err)
                )
        elif type(rc_scripts) is list:
            for i in rc_scripts:
                try:
                    system("/usr/sbin/service", i, 'onestart')
                except SubprocessException as e:
                    raise RpcException(
                        errno.ENOENT,
                        "Whilst starting service {0} command 'service {1} onestart'".format(service, i) +
                        " failed the following error occured: {0}".format(e.err)
                    )

    @private
    @accepts(str)
    def ensure_stopped(self, service):
        # XXX launchd!
        svc = self.datastore.get_one('service_definitions', ('name', '=', service))
        if not svc:
            raise RpcException(errno.ENOENT, 'Service {0} not found'.format(service))

        if 'rcng' not in svc:
            if 'stop_rpc' in svc:
                try:
                    self.dispatcher.call_sync(svc['stop_rpc'])
                    return True
                except RpcException:
                    raise RpcException(
                        errno.ENOENT,
                        "Whilst starting service {0} rpc '{1}' failed".format(service, svc['stop_rpc']) 
                    )
            else:
                return

        rc_scripts = svc['rcng']['rc-scripts']

        if type(rc_scripts) is str:
            try:
                system("/usr/sbin/service", rc_scripts, 'onestop')
            except SubprocessException as e:
                raise RpcException(
                    errno.ENOENT,
                    "Whilst stopping service {0} command 'service {1} onestop'".format(service, rc_scripts) +
                    " failed with error: {0}".format(e.err)
                )

        elif type(rc_scripts) is list:
            for i in rc_scripts:
                try:
                    system("/usr/sbin/service", i, 'onestop')
                except SubprocessException as e:
                    raise RpcException(
                        errno.ENOENT,
                        "Whilst stopping service {0} command 'service {1} onestop'".format(service, i) +
                        " failed the following error occured: {0}".format(e.err)
                    )

    @private
    @accepts(str)
    def reload(self, service):
        svc = self.datastore.get_one('service_definitions', ('name', '=', service))
        status = self.query([('name', '=', service)], {'single': True})
        if not svc:
            raise RpcException(errno.ENOENT, 'Service {0} not found'.format(service))

        rc_scripts = svc['rcng']['rc-scripts']
        reload_scripts = svc['rcng'].get('reload', rc_scripts)

        if status['state'] != 'RUNNING':
            return

        if type(rc_scripts) is str:
            try:
                system("/usr/sbin/service", rc_scripts, 'onereload')
            except SubprocessException as e:
                raise RpcException(
                    errno.ENOENT,
                    "Whilst reloading service {0} command 'service {1} onereload'".format(service, rc_scripts) +
                    " failed with error: {0}".format(e.err)
                )

        elif type(rc_scripts) is list:
            for i in rc_scripts:
                if i not in reload_scripts:
                        continue

                try:
                    system("/usr/sbin/service", i, 'onereload')
                except SubprocessException as e:
                    raise RpcException(
                        errno.ENOENT,
                        "Whilst reloading service {0} command 'service {1} onereload'".format(service, i) +
                        " failed the following error occured: {0}".format(e.err)
                    )

    @private
    @accepts(str)
    def restart(self, service):
        svc = self.datastore.get_one('service_definitions', ('name', '=', service))
        status = self.query([('name', '=', service)], {'single': True})
        if not svc:
            raise RpcException(errno.ENOENT, 'Service {0} not found'.format(service))

        if status['state'] != 'RUNNING':
            return

        hook_rpc = svc.get('restart_rpc')
        if hook_rpc:
            try:
                self.dispatcher.call_sync(hook_rpc)
            except RpcException:
                pass
            return

        rc_scripts = svc['rcng']['rc-scripts']

        if type(rc_scripts) is str:
            try:
                system("/usr/sbin/service", rc_scripts, 'onerestart')
            except SubprocessException as e:
                raise RpcException(
                    errno.ENOENT,
                    "Whilst restarting service {0} command 'service {1} onerestart'".format(service, rc_scripts) +
                    " failed with error: {0}".format(e.err)
                )

        elif type(rc_scripts) is list:
            for i in rc_scripts:
                try:
                    system("/usr/sbin/service", i, 'onerestart')
                except SubprocessException as e:
                    raise RpcException(
                        errno.ENOENT,
                        "Whilst restarting service {0} command 'service {1} onerestart'".format(service, i) +
                        " failed the following error occured: {0}".format(e.err)
                    )

    @private
    @accepts(str, bool, bool)
    def apply_state(self, service, restart=False, reload=False):
        svc = self.datastore.get_one('service_definitions', ('name', '=', service))
        if not svc:
            raise RpcException(errno.ENOENT, 'Service {0} not found'.format(service))

        state, pid = get_status(self.dispatcher, self.datastore, svc)
        node = ConfigNode('service.{0}'.format(service), self.configstore)

        if node['enable'].value and state != 'RUNNING':
            logger.info('Starting service {0}'.format(service))
            self.dispatcher.call_sync('service.ensure_started', service, timeout=120)

        elif not node['enable'].value and state != 'STOPPED':
            logger.info('Stopping service {0}'.format(service))
            self.dispatcher.call_sync('service.ensure_stopped', service, timeout=120)

        else:
            if restart:
                logger.info('Restarting service {0}'.format(service))
                self.dispatcher.call_sync('service.restart', service, timeout=120)
            elif reload:
                logger.info('Reloading service {0}'.format(service))
                self.dispatcher.call_sync('service.reload', service, timeout=120)


@description("Provides functionality to start, stop, restart or reload service")
@accepts(
    str,
    h.enum(str, ['start', 'stop', 'restart', 'reload'])
)
class ServiceManageTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Changing service state'

    def describe(self, id, action):
        svc = self.datastore.get_by_id('service_definitions', id)
        return TaskDescription("{action}ing service {name}", action=action.title(), name=svc['name'])

    def verify(self, id, action):
        return ['system']

    def run(self, id, action):
        if not self.datastore.exists('service_definitions', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Service {0} not found'.format(id))

        service = self.datastore.get_by_id('service_definitions', id)
        state, pid = get_status(self.dispatcher, self.datastore, service)
        hook_rpc = service.get('{0}_rpc'.format(action))
        name = service['name']

        if state == 'RUNNING' and action == 'start':
            return

        if state == 'STOPPED' and action == 'stop':
            return

        if hook_rpc:
            try:
                return self.dispatcher.call_sync(hook_rpc)
            except RpcException as e:
                raise TaskException(errno.EBUSY, 'Hook {0} for {1} failed: {2}'.format(
                    action, name, e
                ))

        if 'rcng' not in service:
            raise TaskException(errno.ENOTSUP, 'Operation not supported by the service')

        rc_scripts = service['rcng'].get('rc-scripts')
        reload_scripts = service['rcng'].get('reload', rc_scripts)
        try:
            if type(rc_scripts) is str:
                system("/usr/sbin/service", rc_scripts, 'one' + action)

            if type(rc_scripts) is list:
                for i in rc_scripts:
                    if action == 'reload' and i not in reload_scripts:
                        continue

                    system("/usr/sbin/service", i, 'one' + action)

        except SubprocessException as e:
            raise TaskException(errno.EBUSY, e.err)

        self.dispatcher.dispatch_event('service.changed', {
            'operation': 'update',
            'ids': [service['id']]
        })


@description("Updates configuration for services")
@accepts(str, h.all_of(
    h.ref('service'),
    h.forbidden('id', 'name', 'builtin', 'pid', 'state')
))
class UpdateServiceConfigTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating service configuration'

    def describe(self, id, updated_fields):
        svc = self.datastore.get_by_id('service_definitions', id)
        return TaskDescription("Updating configuration of service {name}", name=svc['name'])

    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        service_def = self.datastore.get_by_id('service_definitions', id)
        if not service_def:
            raise TaskException(
                errno.ENOENT,
                'Service {0} not found'.format(id)
            )

        if 'config' in updated_fields:
            for x in updated_fields['config']:
                if x == 'type':
                    continue

                if not self.configstore.exists('service.{0}.{1}'.format(service_def['name'], x)):
                    raise TaskException(
                        errno.ENOENT,
                        'Service {0} does not have the following key: {1}'.format(
                            service_def['name'], x))

        node = ConfigNode('service.{0}'.format(service_def['name']), self.configstore)
        restart = False
        reload = False
        updated_config = updated_fields.get('config')

        if updated_config is None:
            return

        updated_config.pop('type', None)

        if service_def.get('task'):
            enable = updated_config.pop('enable', None)

            try:
                self.verify_subtask(service_def['task'], updated_config)
            except RpcException as err:
                new_err = ValidationException()
                new_err.propagate(err, [0], [1, 'config'])
                raise new_err

            result = self.join_subtasks(self.run_subtask(service_def['task'], updated_config))
            restart = result[0] == 'RESTART'
            reload = result[0] == 'RELOAD'

            if enable is not None:
                node['enable'] = enable
        else:
            node.update(updated_config)

            if service_def.get('etcd-group'):
                self.dispatcher.call_sync('etcd.generation.generate_group', service_def.get('etcd-group'))

            if 'enable' in updated_config:
                # Propagate to dependent services
                for i in service_def.get('dependencies', []):
                    svc_dep = self.datastore.get_by_id('service_definitions', i)
                    self.join_subtasks(self.run_subtask('service.update', i, {
                        'config': {
                            'type': 'service-{0}'.format(svc_dep['name']),
                            'enable': updated_config['enable']
                        }
                    }))

                if service_def.get('auto_enable'):
                    # Consult state of services dependent on us
                    for i in self.datastore.query('service_definitions', ('dependencies', 'in', service_def['name'])):
                        enb = self.configstore.get('service.{0}.enable', i['name'])
                        if enb != updated_config['enable']:
                            del updated_config['enable']
                            break

        self.dispatcher.call_sync('etcd.generation.generate_group', 'services')
        self.dispatcher.call_sync('service.apply_state', service_def['name'], restart, reload, timeout=120)
        self.dispatcher.dispatch_event('service.changed', {
            'operation': 'update',
            'ids': [service_def['id']]
        })


def get_status(dispatcher, datastore, service):
    if 'status_rpc' in service:
        state = 'RUNNING'
        pid = None
        try:
            dispatcher.call_sync(service['status_rpc'])
        except RpcException:
            state = 'STOPPED'

    elif 'pidfile' in service:
        state = 'RUNNING'
        pid = None
        pidfiles = service['pidfile'] \
            if isinstance(service['pidfile'], list) \
            else [service['pidfile']]

        for p in pidfiles:
            # Check if process is alive by reading pidfile
            try:
                with open(p, 'r') as fd:
                    pid = int(fd.read().strip())
            except IOError:
                pid = None
                state = 'STOPPED'
            except ValueError:
                pid = None
                state = 'STOPPED'
            else:
                try:
                    os.kill(pid, 0)
                except OSError:
                    state = 'UNKNOWN'

    elif 'rcng' in service and 'rc-scripts' in service['rcng']:
        rc_scripts = service['rcng']['rc-scripts']
        pid = None
        state = 'RUNNING'
        try:
            if type(rc_scripts) is str:
                system("/usr/sbin/service", rc_scripts, 'onestatus')

            if type(rc_scripts) is list:
                for x in rc_scripts:
                    system("/usr/sbin/service", x, 'onestatus')
        except SubprocessException:
            state = 'STOPPED'

    elif 'dependencies' in service:
        pid = None
        state = 'RUNNING'

        for i in service['dependencies']:
            d_service = datastore.get_one('service_definitions', ('id', '=', i))
            d_state, d_pid = get_status(dispatcher, datastore, d_service)
            if d_state != 'RUNNING':
                state = d_state

    else:
        pid = None
        state = 'UNKNOWN'

    return state, pid


def collect_debug(dispatcher):
    yield AttachFile('rc.conf', '/etc/rc.conf')
    yield AttachCommandOutput('enabled-services', ['/usr/sbin/service', '-e'])


def _init(dispatcher, plugin):
    def on_rc_command(args):
        cmd = args['action']
        name = args['name']
        svc = dispatcher.datastore.get_one('service_definitions', (
            'or', (
                ('rcng.rc-scripts', '=', name),
                ('rcng.rc-scripts', 'in', name)
            )
        ))

        if svc is None:
            # ignore unknown rc scripts
            return

        if cmd not in ('start', 'stop', 'reload', 'restart'):
            # ignore unknown actions
            return

        if cmd == 'stop':
            cmd += 'p'

        dispatcher.dispatch_event('service.{0}ed'.format(cmd), {
            'name': svc['name']
        })

    plugin.register_schema_definition('service', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'pid': {'type': 'integer'},
            'builtin': {'type': 'boolean'},
            'state': {'$ref': 'service-state'},
            'config': {'$ref': 'service-config'}
        }
    })

    plugin.register_schema_definition('service-state', {
        'type': 'string',
        'enum': ['RUNNING', 'STOPPED', 'UNKNOWN']
    })

    plugin.register_schema_definition('service-config', {
        'discriminator': 'type',
        'oneOf': [
            {'$ref': 'service-{0}'.format(svc['name'])}
            for svc in dispatcher.datastore.query('service_definitions')
            if not svc['builtin']
        ]
    })

    plugin.register_event_handler("service.rc.command", on_rc_command)
    plugin.register_task_handler("service.manage", ServiceManageTask)
    plugin.register_task_handler("service.update", UpdateServiceConfigTask)
    plugin.register_provider("service", ServiceInfoProvider)
    plugin.register_event_type("service.changed")

    for svc in dispatcher.datastore.query('service_definitions'):
        plugin.register_resource(Resource('service:{0}'.format(svc['name'])), parents=['system'])

    plugin.register_debug_hook(collect_debug)
