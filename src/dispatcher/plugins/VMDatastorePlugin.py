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

import contextlib
from task import Task, TaskException, Provider, query
from freenas.dispatcher.rpc import accepts, returns, private, description, generator


class DatastoreProvider(Provider):
    @query('vm-datastore')
    @generator
    def query(self, filter=None, params=None):
        for i in self.supported_drivers():
            with contextlib.suppress(BaseException):
                yield from self.dispatcher.call_sync('vm.datastore.{0}.discover'.format(i))

    @description("Returns list of supported datastore drivers")
    def supported_drivers(self):
        result = {}
        for p in list(self.dispatcher.plugins.values()):
            if p.metadata and p.metadata.get('type') == 'datastore':
                result[p.metadata['driver']] = {}

        return result

    @private
    def get_driver(self, id):
        return 'volume'

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
            datastore_path
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
        pass


class DirectoryCreateTask(Task):
    def verify(self, id, path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.create_directory'.format(driver), id, path)


class DirectoryDeleteTask(Task):
    def verify(self, id, path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.delete_directory'.format(driver), id, path)


class BlockDeviceCreateTask(Task):
    def verify(self, id, path, size):
        return []

    def run(self, id, path, size):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync(
            'vm.datastore.{0}.create_block_device'.format(driver), id, path, size)


class BlockDeviceDeleteTask(Task):
    def verify(self, id, path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.delete_block_device'.format(driver), id, path)


class BlockDeviceCloneTask(Task):
    def verify(self, id, path, new_path):
        return []

    def run(self, id, path):
        driver = self.dispatcher.call_sync('vm.datastore.get_driver', id)
        return self.run_subtask_sync('vm.datastore.{0}.clone_block_device'.format(driver), id, path)


def _init(dispatcher, plugin):
    plugin.register_schema_definition('vm-datastore-type', {
        'type': 'string',
        'enum': ['DIRECTORY', 'VOLUME', 'NFS']
    })

    plugin.register_schema_definition('vm-datastore', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'type': {'$ref': 'vm-datastore-type'}
        }
    })

    plugin.register_provider('vm.datastore', DatastoreProvider)
    plugin.register_task_handler('vm.datastore.create_directory', DirectoryCreateTask)
    plugin.register_task_handler('vm.datastore.delete_directory', DirectoryDeleteTask)
    plugin.register_task_handler('vm.datastore.create_block_device', BlockDeviceCreateTask)
    plugin.register_task_handler('vm.datastore.delete_block_device', BlockDeviceDeleteTask)
    plugin.register_task_handler('vm.datastore.clone_block_device', BlockDeviceCloneTask)
