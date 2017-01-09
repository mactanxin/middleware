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

import socket
import errno
import iscsi
from task import Provider, Task, TaskDescription, TaskException
from freenas.dispatcher.rpc import SchemaHelper as h, description, generator, accepts, returns
from freenas.utils import normalize, first_or_default


class ISCSITargetProvider(Provider):
    @generator
    def query(self, filter=None, params=None):
        ctx = iscsi.ISCSIInitiator()
        sessions = self.dispatcher.threaded(lambda: list(ctx.sessions))

        def extend(obj):
            ses = first_or_default(lambda s: s.config.target == obj['name'], sessions)
            obj['status'] = {
                'connected': ses.connected if ses else False,
                'status': ses.reason if ses else 'Unknown'
            }

            return obj

        return self.datastore.query_stream(
            'iscsi_initiator.targets',
            *(filter or []),
            callback=extend,
            **(params or {})
        )


@description("Creates a new iSCSI initiator target")
@accepts(h.all_of(
    h.ref('iscsi-target'),
    h.required('address', 'name')
))
class ISCSITargetCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating iSCSI initiator target"

    def describe(self, target):
        return TaskDescription("Creating iSCSI initiator target {name}", name=target['name'])

    def verify(self, target):
        return ['system']

    def run(self, target):
        normalize(target, {
            'enabled': True,
            'user': None,
            'secret': None,
            'mutual_user': None,
            'mutual_secret': None
        })

        # if iscsid service is not enabled, enable it now.
        service_state = self.dispatcher.call_sync('service.query', [('name', '=', 'iscsid')], {'single': True})
        if service_state['state'] != 'RUNNING':
            config = service_state['config']
            config['enable'] = True
            self.run_subtask_sync('service.update', service_state['id'], {'config': config})

        id = self.datastore.insert('iscsi_initiator.targets', target)
        ctx = iscsi.ISCSIInitiator()
        session = iscsi_convert_session(target)
        ctx.add_session(session)

        self.dispatcher.emit_event('disk.iscsi.target.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@description("Updates configuration of a iSCSI initiator target")
@accepts(str, h.ref('iscsi-target'))
class ISCSITargetUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating iSCSI initiator target"

    def describe(self, id, updated_params):
        pass

    def verify(self, id, updated_params):
        return ['system']

    def run(self, id, updated_params):
        target = self.datastore.get_by_id('iscsi_initiator.targets', id)
        if not target:
            raise TaskException(errno.ENOENT, 'Target {0} doesn\'t exist'.format(id))

        target.update(updated_params)
        self.datastore.update('iscsi_initiator.targets', id, target)

        ctx = iscsi.ISCSIInitiator()
        session = first_or_default(lambda s: s.config.target == target['name'], ctx.sessions)
        session = iscsi_convert_session(target, session)
        if session.id:
            ctx.modify_session(session)
        else:
            ctx.add_session(session)

        self.dispatcher.emit_event('disk.iscsi.target.changed', {
            'operation': 'update',
            'ids': [id]
        })


@description("Removes iSCSI initiator target")
@accepts(str)
class ISCSITargetDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting iSCSI initiator target"

    def describe(self, id):
        pass

    def verify(self, id):
        return ['system']

    def run(self, id):
        target = self.datastore.get_by_id('iscsi_initiator.targets', id)
        if not target:
            raise TaskException(errno.ENOENT, 'Target {0} doesn\'t exist'.format(id))

        self.datastore.delete('iscsi_initiator.targets', id)

        ctx = iscsi.ISCSIInitiator()
        session = first_or_default(lambda s: s.config.target == target['name'], ctx.sessions)
        if session:
            ctx.remove_session(session)

        self.dispatcher.emit_event('disk.iscsi.target.changed', {
            'operation': 'delete',
            'ids': [id]
        })


def iscsi_convert_session(target, session=None):
    if not session:
        session = iscsi.ISCSISessionConfig()

    session.initiator = 'iqn.2005-10.org.freenas:{0}'.format(socket.gethostname())
    session.enable = target['enabled']
    session.target = target['name']
    session.target_address = target['address']
    session.user = target['user']
    session.secret = target['secret']
    session.mutual_user = target['mutual_user']
    session.mutual_secret = target['mutual_secret']
    return session


def _depends():
    return ['DiskPlugin']


def _init(dispatcher, plugin):
    plugin.register_schema_definition('iscsi-target', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'address': {'type': 'string'},
            'name': {'type': 'string'},
            'enabled': {'type': 'boolean'},
            'user': {'type': ['string', 'null']},
            'secret': {'type': ['string', 'null']},
            'mutual_user': {'type': ['string', 'null']},
            'mutual_secret': {'type': ['string', 'null']},
            'status': {'$ref': 'iscsi-target-status'}
        }
    })

    plugin.register_schema_definition('iscsi-target-status', {
        'type': 'object',
        'additionalProperties': False,
        'readOnly': True,
        'properties': {
            'connected': {'type': 'boolean'},
            'status': {'type': 'string'},
        }
    })

    def on_session_update(args):
        target = dispatcher.datastore.query('iscsi_initiator.targets', ('name', '=', args['target']), single=True)
        if target:
            dispatcher.emit_event('disk.iscsi.target.changed', {
                'operation': 'update',
                'ids': [target['id']]
            })

    plugin.register_provider('disk.iscsi.target', ISCSITargetProvider)
    plugin.register_event_type('disk.iscsi.target.changed')
    plugin.register_task_handler('disk.iscsi.target.create', ISCSITargetCreateTask)
    plugin.register_task_handler('disk.iscsi.target.update', ISCSITargetUpdateTask)
    plugin.register_task_handler('disk.iscsi.target.delete', ISCSITargetDeleteTask)
    plugin.register_event_handler('iscsi.session.update', on_session_update)

    ctx = iscsi.ISCSIInitiator()
    for i in dispatcher.datastore.query_stream('iscsi_initiator.targets'):
        session = iscsi_convert_session(i)
        ctx.add_session(session)
