#
# Copyright 2017 iXsystems, Inc.
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
                'connected': ses.connected,
                'status': ses.reason
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
        pass

        id = self.datastore.insert('iscsi_initiator.targets', target)
        iscsi_add_session(target)

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

    def describe(self, *args, **kwargs):
        pass

    def verify(self, target):
        return ['system']

    def run(self, target):
        pass


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
        if not self.datastore.get_by_id('iscsi_initiator.targets', id):
            raise TaskException(errno.ENOENT, 'Target {0} doesn\'t exist'.format(id))


def iscsi_add_session(target):
    ctx = iscsi.ISCSIInitiator()
    session = iscsi.ISCSISessionConfig()
    session.initiator = 'iqn.2005-10.org.freenas:{0}'.format(socket.gethostname())
    session.target = target['name']
    session.target_address = target['address']
    session.user = target['user']
    session.secret = target['secret']
    session.mutual_user = target['mutual_user']
    session.mutual_secret = target['mutual_secret']
    ctx.add_session(session)


def iscsi_remove_session(target):
    ctx = iscsi.ISCSIInitiator()
    pass


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

    plugin.register_provider('disk.iscsi.target', ISCSITargetProvider)
    plugin.register_event_type('disk.iscsi.target.changed')
    plugin.register_task_handler('disk.iscsi.target.create', ISCSITargetCreateTask)
    plugin.register_task_handler('disk.iscsi.target.update', ISCSITargetUpdateTask)
    plugin.register_task_handler('disk.iscsi.target.delete', ISCSITargetDeleteTask)

    for i in dispatcher.datastore.query('iscsi_initiator.targets'):
        iscsi_add_session(i)
