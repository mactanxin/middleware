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
import contextlib
from task import ProgressTask, TaskException, Provider, query, TaskDescription
from freenas.dispatcher.rpc import RpcException, accepts, returns, private, description, generator
from freenas.utils import query as q


class DatastoreProvider(Provider):
    @query('vm-datastore')
    @generator
    def query(self, filter=None, params=None):
        drivers = self.supported_drivers()

        def extend(obj):
            obj['capabilities'] = drivers[obj['type']]
            return obj

        def doit():
            for i in drivers:
                with contextlib.suppress(BaseException):
                    for d in self.dispatcher.call_sync('vm.datastore.{0}.discover'.format(i)):
                        yield extend(d)

            yield from self.datastore.query_stream('vm.datastores', callback=extend)

        return q.query(doit(), *(filter or []), **(params or {}))

    @description("Returns list of supported datastore drivers")
    def supported_drivers(self):
        result = {}
        for p in list(self.dispatcher.plugins.values()):
            if p.metadata and p.metadata.get('type') == 'datastore':
                result[p.metadata['driver']] = {
                    'block_devices': p.metadata['block_devices'],
                    'clones': p.metadata['clones'],
                    'snapshots': p.metadata['snapshots']
                }

        return result

    @private
    def get_driver(self, id):
        ds = self.query([('id', '=', id)], {'single': True})
        if not ds:
            raise RpcException(errno.ENOENT, 'Datastore {0} not found'.format(id))

        return ds['type']

    @private
    def directory_exists(self, datastore_id, datastore_path):
        driver = self.get_driver(datastore_id)
        return self.dispatcher.call_sync(
            'vm.datastore.{0}.directory_exists'.format(driver),
            datastore_id,
            datastore_path
        )

    @private
    @accepts(str, str)
    def get_filesystem_path(self, datastore_id, datastore_path):
        driver = self.get_driver(datastore_id)
        return self.dispatcher.call_sync(
            'vm.datastore.{0}.get_filesystem_path'.format(driver),
            datastore_id,
            normpath(datastore_path)
        )

    @private
    @accepts(str)
    def get_resources(self, datastore_id):
        driver = self.get_driver(datastore_id)
        return self.dispatcher.call_sync(
            'vm.datastore.{0}.get_resources'.format(driver),
            datastore_id
        )

    @private
    @generator
    def get_snapshots(self, datastore_id, path):
        driver = self.get_driver(datastore_id)
        return self.dispatcher.call_sync(
            'vm.datastore.{0}.get_snapshots'.format(driver),
            datastore_id,
            path
        )


class DatastoreBaseTask(ProgressTask):
    def __init__(self, dispatcher, datastore):
        super(DatastoreBaseTask, self).__init__(dispatcher, datastore)

    def get_driver_and_check_capabilities(self, id, block_devices=False, clones=False, snapshots=False):
        ds = self.dispatcher.call_sync('vm.datastore.query', [('id', '=', id)], {'single': True})
        if not ds:
            raise RpcException(errno.ENOENT, 'Datastore {0} not found'.format(id))

        capabilities = ds['capabilities']
        name = ds['name']

        if block_devices and 'block_devices' not in capabilities:
            raise TaskException(errno.ENOTSUP, 'Datastore {0} does not support block devices'.format(name))

        if clones and 'clones' not in capabilities:
            raise TaskException(errno.ENOTSUP, 'Datastore {0} does not support clones'.format(name))

        if snapshots and 'snapshots' not in capabilities:
            raise TaskException(errno.ENOTSUP, 'Datastore {0} does not support snapshots'.format(name))

        return ds['type']

    def get_resources(self, id):
        try:
            res = self.dispatcher.call_sync('vm.datastore.get_resources', id)
        except RpcException:
            res = ['system']

        return res


class DatastoreCreateTask(DatastoreBaseTask):
    def verify(self, datastore):
        return ['system']

    def run(self, datastore):
        self.run_subtask_sync('vm.datastore.{0}.create'.format(datastore['type']), datastore)
        id = self.datastore.insert('vm.datastores', datastore)
        self.dispatcher.emit_event('vm.datastore.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


class DatastoreUpdateTask(DatastoreBaseTask):
    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        ds = self.datastore.get_by_id('vm.datastores', id)
        if not ds:
            raise TaskException(errno.ENOENT, 'Datastore {0} not found'.format(id))

        self.run_subtask_sync('vm.datastore.{0}.update'.format(ds['type']), id, updated_fields)

        ds.update(updated_fields)
        self.datastore.update('vm.datastores', id, ds)
        self.dispatcher.emit_event('vm.datastore.changed', {
            'operation': 'update',
            'ids': [id]
        })

        return id


class DatastoreDeleteTask(DatastoreBaseTask):
    def verify(self, id):
        return ['system']

    def run(self, id):
        ds = self.datastore.get_by_id('vm.datastores', id)
        if not ds:
            raise TaskException(errno.ENOENT, 'Datastore {0} not found'.format(id))

        self.run_subtask_sync('vm.datastore.{0}.delete'.format(ds['type']), id)
        self.datastore.delete('vm.datastores', id)
        self.dispatcher.emit_event('vm.datastore.changed', {
            'operation': 'delete',
            'ids': [id]
        })


class DirectoryCreateTask(DatastoreBaseTask):
    def verify(self, id, path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.create_directory'.format(driver), id, normpath(path))


class DirectoryDeleteTask(DatastoreBaseTask):
    def verify(self, id, path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.delete_directory'.format(driver), id, normpath(path))


class DirectoryRenameTask(DatastoreBaseTask):
    def verify(self, id, old_path, new_path):
        return []

    def run(self, id, old_path, new_path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync(
            'vm.datastore.{0}.rename_directory'.format(driver),
            id,
            normpath(old_path),
            normpath(new_path)
        )


class BlockDeviceCreateTask(DatastoreBaseTask):
    def verify(self, id, path, size):
        return []

    def run(self, id, path, size):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync(
            'vm.datastore.{0}.create_block_device'.format(driver), id, normpath(path), size)


class BlockDeviceDeleteTask(DatastoreBaseTask):
    def verify(self, id, path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.delete_block_device'.format(driver), id, normpath(path))


class BlockDeviceRenameTask(DatastoreBaseTask):
    def verify(self, id, old_path, new_path):
        return []

    def run(self, id, old_path, new_path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync(
            'vm.datastore.{0}.resize_block_device'.format(driver),
            id,
            normpath(old_path),
            normpath(new_path)
        )


class BlockDeviceResizeTask(Task):
    def verify(self, id, path, size):
        return []

    def run(self, id, path, new_size):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync(
            'vm.datastore.{0}.resize_block_device'.format(driver),
            id,
            normpath(path),
            new_size
        )


class BlockDeviceCloneTask(DatastoreBaseTask):
    def verify(self, id, path, new_path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.clone_block_device'.format(driver), id, path)


class SnapshotCreateTask(Task):
    def verify(self, id, path, new_path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.create_snapshot'.format(driver), id, path)


class SnapshotDeleteTask(Task):
    def verify(self, id, path, new_path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.delete_snapshot'.format(driver), id, path)


def normpath(p):
    return p[1:] if p.startswith('/') else p


def _init(dispatcher, plugin):
    def update_datastore_properties_schema():
        plugin.register_schema_definition('vm-datastore-properties', {
            'discriminator': '%type',
            'oneOf': [
                {'$ref': 'vm-datastore-properties-{0}'.format(name)}
                for name
                in dispatcher.call_sync('vm.datastore.supported_drivers')
            ]
        })

    plugin.register_schema_definition('vm-datastore-state', {
        'type': 'string',
        'enum': ['ONLINE', 'OFFLINE']
    })

    plugin.register_schema_definition('vm-datastore-capabilities', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'block_devices': {'type': 'boolean'},
            'clones': {'type': 'boolean'},
            'snapshots': {'type': 'boolean'},
        }
    })

    plugin.register_schema_definition('vm-datastore', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'type': {'type': 'string'},
            'state': {'$ref': 'vm-datastore-state'},
            'capabilities': {'$ref': 'vm-datastore-capabilities'},
            'properties': {'$ref': 'vm-datastore-properties'}
        }
    })

    plugin.register_provider('vm.datastore', DatastoreProvider)
    plugin.register_task_handler('vm.datastore.create', DatastoreCreateTask)
    plugin.register_task_handler('vm.datastore.update', DatastoreUpdateTask)
    plugin.register_task_handler('vm.datastore.delete', DatastoreDeleteTask)
    plugin.register_task_handler('vm.datastore.create_directory', DirectoryCreateTask)
    plugin.register_task_handler('vm.datastore.delete_directory', DirectoryDeleteTask)
    plugin.register_task_handler('vm.datastore.rename_directory', DirectoryRenameTask)
    plugin.register_task_handler('vm.datastore.create_block_device', BlockDeviceCreateTask)
    plugin.register_task_handler('vm.datastore.delete_block_device', BlockDeviceDeleteTask)
    plugin.register_task_handler('vm.datastore.rename_block_device', BlockDeviceRenameTask)
    plugin.register_task_handler('vm.datastore.resize_block_device', BlockDeviceResizeTask)
    plugin.register_task_handler('vm.datastore.clone_block_device', BlockDeviceCloneTask)
    plugin.register_event_type('vm.datastore.changed')

    update_datastore_properties_schema()
    dispatcher.register_event_handler('server.plugin.loaded', update_datastore_properties_schema)
