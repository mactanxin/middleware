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
import logging
import signal
from task import Task, Provider, TaskException, TaskDescription, ValidationException, query
from debug import AttachFile, AttachCommandOutput
from resources import Resource
from freenas.dispatcher.rpc import RpcException, description, accepts, private, returns, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from datastore.config import ConfigNode
from freenas.utils import extend as extend_dict, first_or_default, query as q


logger = logging.getLogger('ServiceManagePlugin')


@description("Provides info about available services and their state")
class ServiceInfoProvider(Provider):
    @description("Lists available services")
    @query("service")
    @generator
    def query(self, filter=None, params=None):
        def extend(i):
            state, error, pid = get_status(self.dispatcher, self.datastore, i)
            entry = {
                'id': i['id'],
                'name': i['name'],
                'state': state,
                'error': error
            }

            if pid is not None:
                entry['pid'] = pid

            entry['builtin'] = i['builtin']
            entry['config'] = self.get_service_config(i['id'])
            return entry

        return self.datastore.query_stream('service_definitions', *(filter or []), callback=extend, **(params or {}))

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

        if 'launchd' in svc:
            launchd = svc['launchd']
            plists = [launchd] if isinstance(launchd, dict) else launchd

            for i in plists:
                self.dispatcher.call_sync('serviced.job.start', i['Label'])

            return

        if 'start_rpc' in svc:
            try:
                self.dispatcher.call_sync(svc['start_rpc'])
                return True
            except RpcException:
                raise RpcException(
                    errno.ENOENT,
                    "Whilst starting service {0} rpc '{1}' failed".format(service, svc['start_rpc'])
                )

    @private
    @accepts(str)
    def ensure_stopped(self, service):
        # XXX launchd!
        svc = self.datastore.get_one('service_definitions', ('name', '=', service))
        if not svc:
            raise RpcException(errno.ENOENT, 'Service {0} not found'.format(service))

        if 'launchd' in svc:
            launchd = svc['launchd']
            plists = [launchd] if isinstance(launchd, dict) else launchd

            for i in plists:
                self.dispatcher.call_sync('serviced.job.stop', i['Label'])

            return

        if 'stop_rpc' in svc:
            try:
                self.dispatcher.call_sync(svc['stop_rpc'])
                return True
            except RpcException:
                raise RpcException(
                    errno.ENOENT,
                    "Whilst starting service {0} rpc '{1}' failed".format(service, svc['stop_rpc'])
                )

    @private
    @accepts(str)
    def reload(self, service):
        svc = self.query([('name', '=', service)], {'single': True})
        if not svc:
            raise RpcException(errno.ENOENT, 'Service {0} not found'.format(service))

        if svc['state'] != 'RUNNING':
            return

        if svc['pid']:
            for p in svc['pid']:
                try:
                    os.kill(p, signal.SIGHUP)
                except ProcessLookupError:
                    continue

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

        if 'launchd' in svc:
            launchd = svc['launchd']
            plists = [launchd] if isinstance(launchd, dict) else launchd

            for i in plists:
                self.dispatcher.call_sync('serviced.job.stop', i['Label'])
                self.dispatcher.call_sync('serviced.job.start', i['Label'])

            return

    @private
    @accepts(str, bool, bool)
    def apply_state(self, service, restart=False, reload=False):
        svc = self.datastore.get_one('service_definitions', ('name', '=', service))
        if not svc:
            raise RpcException(errno.ENOENT, 'Service {0} not found'.format(service))

        state, _, pid = get_status(self.dispatcher, self.datastore, svc)
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
        state, _, pid = get_status(self.dispatcher, self.datastore, service)
        hook_rpc = service.get('{0}_rpc'.format(action))
        name = service['name']

        if state == 'RUNNING' and action == 'start':
            return

        if state == 'STOPPED' and action == 'stop':
            return

        if state != 'RUNNING' and action == 'reload':
            raise TaskException(errno.EINVAL, 'Only running services can be reloaded')

        if hook_rpc:
            try:
                self.dispatcher.call_sync(hook_rpc)
            except RpcException as e:
                raise TaskException(errno.EBUSY, 'Hook {0} for {1} failed: {2}'.format(
                    action, name, e
                ))

        if 'launchd' in service:
            launchd = service['launchd']
            plists = [launchd] if isinstance(launchd, dict) else launchd

            for i in plists:
                if action == 'reload':
                    pass

                if action in ('stop', 'restart'):
                    self.dispatcher.call_sync('serviced.job.stop', i['Label'])

                if action in ('start', 'restart'):
                    self.dispatcher.call_sync('serviced.job.start', i['Label'])

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

        enable = not node['enable'].value and updated_config['enable']
        disable = node['enable'].value and not updated_config['enable']
        updated_config.pop('type', None)

        if service_def.get('task'):
            try:
                self.verify_subtask(service_def['task'], updated_config)
            except RpcException as err:
                new_err = ValidationException()
                new_err.propagate(err, [0], [1, 'config'])
                raise new_err

            result = self.join_subtasks(self.run_subtask(service_def['task'], updated_config))
            restart = result[0] == 'RESTART'
            reload = result[0] == 'RELOAD'

            if updated_config.get('enable') is not None:
                node['enable'] = updated_config['enable']
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

        if 'launchd' in service_def:
            if enable:
                load_job(self.dispatcher, service_def)

            if disable:
                unload_job(self.dispatcher, service_def)

        self.dispatcher.call_sync('etcd.generation.generate_group', 'services')
        self.dispatcher.call_sync('service.apply_state', service_def['name'], restart, reload, timeout=120)
        self.dispatcher.dispatch_event('service.changed', {
            'operation': 'update',
            'ids': [service_def['id']]
        })


def load_job(dispatcher, svc):
    if isinstance(svc['launchd'], dict):
        svc['launchd'] = [svc['launchd']]

    for plist in svc['launchd']:
        try:
            dispatcher.call_sync('serviced.job.load', plist)
        except RpcException as err:
            if err.code != errno.EEXIST:
                raise


def unload_job(dispatcher, svc):
    if isinstance(svc['launchd'], dict):
        svc['launchd'] = [svc['launchd']]

    for plist in svc['launchd']:
        try:
            dispatcher.call_sync('serviced.job.unload', plist['Label'])
        except RpcException as err:
            if err.code != errno.ENOENT:
                raise


def get_status(dispatcher, datastore, service):
    if 'status_rpc' in service:
        state = 'RUNNING'
        error = None
        pid = None
        try:
            dispatcher.call_sync(service['status_rpc'])
        except RpcException:
            state = 'STOPPED'

    elif 'launchd' in service:
        state = 'UNKNOWN'
        error = None
        pid = None

        try:
            launchd = service['launchd']
            plists = [launchd] if isinstance(launchd, dict) else launchd
            pids = []
            errors = []
            states = []

            for i in plists:
                job = dispatcher.call_sync('serviced.job.get', i['Label'])
                states.append(job['State'])
                errors.append(job.get('FailureReason'))
                if job['PID']:
                    pids.append(job['PID'])

            for i in ('RUNNING', 'STOPPED', 'STARTING', 'STOPPING'):
                if all(s == i for s in states):
                    state = i
                    pid = pids

            if any(s == 'ERROR' for s in states):
                state = 'ERROR'
                error = first_or_default(lambda e: e, errors)
                pid = None

        except RpcException as err:
            state = 'STOPPED' if err.code == errno.ENOENT else 'UNKNOWN'
            pid = None
        except KeyError:
            state = 'UNKNOWN'
            pid = None

    elif 'dependencies' in service:
        pid = None
        error = None
        state = 'RUNNING'

        for i in service['dependencies']:
            d_service = datastore.get_one('service_definitions', ('id', '=', i))
            d_state, d_error, d_pid = get_status(dispatcher, datastore, d_service)
            if d_state != 'RUNNING':
                state = d_state
                error = d_error

    else:
        pid = None
        error = None
        state = 'UNKNOWN'

    return state, error, pid


def collect_debug(dispatcher):
    yield AttachFile('rc.conf', '/etc/rc.conf')
    yield AttachCommandOutput('servicectl-list', ['/usr/local/sbin/servicectl', 'list'])


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

    def on_ready(args):
        for svc in dispatcher.datastore.query('service_definitions'):
            logger.debug('Loading service {0}'.format(svc['name']))
            enb = svc.get('builtin') or dispatcher.configstore.get('service.{0}.enable'.format(svc['name']))

            if 'launchd' in svc and enb:
                try:
                    load_job(dispatcher, svc)
                except RpcException as err:
                    logger.error('Cannot load service {0}: {1}'.format(svc['name'], err))
                    continue

            plugin.register_resource(Resource('service:{0}'.format(svc['name'])), parents=['system'])

    def on_job_changed(args):
        svc = dispatcher.datastore.get_one('service_definitions', ('launchd.Label', '=', args['Label']))
        if svc:
            dispatcher.emit_event('service.changed', {
                'operation': 'update',
                'ids': [svc['id']]
            })

    plugin.register_schema_definition('service', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'error': {'type': ['string', 'null']},
            'pid': {
                'type': ['array', 'null'],
                'items': {'type': 'integer'}
            },
            'builtin': {'type': 'boolean'},
            'state': {'$ref': 'service-state'},
            'config': {'$ref': 'service-config'}
        }
    })

    plugin.register_schema_definition('service-state', {
        'type': 'string',
        'enum': ['RUNNING', 'STARTING', 'STOPPING', 'STOPPED', 'ERROR', 'UNKNOWN']
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
    plugin.register_event_handler("serviced.job.started", on_job_changed)
    plugin.register_event_handler("serviced.job.stopped", on_job_changed)
    plugin.register_event_handler("serviced.job.error", on_job_changed)
    plugin.register_event_handler("server.ready", on_ready)
    plugin.register_task_handler("service.manage", ServiceManageTask)
    plugin.register_task_handler("service.update", UpdateServiceConfigTask)
    plugin.register_provider("service", ServiceInfoProvider)
    plugin.register_event_type("service.changed")

    plugin.register_debug_hook(collect_debug)
