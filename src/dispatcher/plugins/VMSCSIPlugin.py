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

import errno
from task import Provider, Task, TaskException, query
from freenas.dispatcher.rpc import accepts, returns, generator, SchemaHelper as h
from freenas.utils import normalize


class VMSCSIPortProvider(Provider):
    @query('VmScsiPort')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('vm.scsi_ports', *(filter or []), **(params or {}))


@accepts(h.ref('VmScsiPort'))
@returns(str)
class VMSCSIPortCreateTask(Task):
    def verify(self, port):
        return []

    def run(self, port):
        normalize(port, {
            'luns': []
        })

        id = self.datastore.insert('vm.scsi_ports', port)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.emit_event('vm.scsi.port.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@accepts(str, h.ref('VmScsiPort'))
class VMSCSIPortUpdateTask(Task):
    def verify(self, id, updated_fields):
        return []

    def run(self, id, updated_fiels):
        port = self.datastore.get_by_id('vm.scsi_ports', id)
        if not port:
            raise TaskException(errno.ENOENT, 'Port {0} not found'.format(id))

        port.update(updated_fiels)
        self.datastore.update('vm.scsi_ports', id, port)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.emit_event('vm.scsi.port.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
class VMSCSIPortDeleteTask(Task):
    def verify(self, id):
        return []

    def run(self, id):
        port = self.datastore.get_by_id('vm.scsi_ports', id)
        if not port:
            raise TaskException(errno.ENOENT, 'Port {0} not found'.format(id))

        self.datastore.delete('vm.scsi_ports', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'ctl')
        self.dispatcher.emit_event('vm.scsi.port.changed', {
            'operation': 'delete',
            'ids': [id]
        })


def _init(dispatcher, plugin):
    plugin.register_schema_definition('VmScsiPort', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'number': {'type': 'integer'},
            'description': {'type': ['string', 'null']},
            'luns': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'additionalProperties': False,
                    'properties': {
                        'number': {'type': 'integer'},
                        'lun_id': {'type': 'string'}
                    }
                }
            }
        }
    })

    plugin.register_provider('vm.scsi.port', VMSCSIPortProvider)
    plugin.register_task_handler('vm.scsi.port.create', VMSCSIPortCreateTask)
    plugin.register_task_handler('vm.scsi.port.update', VMSCSIPortUpdateTask)
    plugin.register_task_handler('vm.scsi.port.delete', VMSCSIPortDeleteTask)
    plugin.register_event_type('vm.scsi.port.changed')
