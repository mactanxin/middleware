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

import errno
import iscsi
from freenas.dispatcher.rpc import SchemaHelper as h, generator, accepts, returns
from task import Provider, Task, TaskDescription, TaskException


class ISCSIInitiatorProvider(Provider):
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('iscsi_initiator.targets', *(filter or []), **(params or {}))


@accepts(h.ref('iscsi-target'))
class ISCSITargetCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating iSCSI initiator target"

    def describe(self, target):
        return TaskDescription("Creating iSCSI initiator target {name}", name=target['name'])

    def verify(self, target):
        return ['system']

    def run(self, target):
        if self.datastore.get_by_id('iscsi_initiator.targets', target['id']):
            raise TaskException(errno.EEXIST, 'Target {0} already exists'.format(target['id']))

        self.datastore.insert('iscsi_initiator.targets', target)
        iscsi_add_session(target)
        return target['id']


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
            raise TaskException(errno.ENOENT, 'Target {0} doesn\'t exist'.format(id)


def iscsi_add_session(target):
    ctx = iscsi.ISCSIInitiator()
    session = iscsi.ISCSISession()
    session.target = target['name']
    session.target_address = target['addresss']
    session.user = target['user']
    session.secret = target['secret']
    session.mutual_user = target['mutual_user']
    session.mutual_secret = target['mutual_secret']
    ctx.session_add(session)


def iscsi_remove_session(target):
    ctx = iscsi.ISCSIInitiator()
    pass


def _init(dispatcher, plugin):
    plugin.register_schema_definition('iscsi-target', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'address': {'type': 'string'},
            'name': {'type': 'name'},
            'user': {'type': ['string', 'null']},
            'secret': {'type': ['string', 'null']},
            'mutual_user': {'type': ['string', 'null']},
            'mutual_secret': {'type': ['string', 'null']},
        }
    })

    plugin.register_schema_definition('iscsi-session', {

    })
