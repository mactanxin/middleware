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

import os
import shutil
import errno
from task import Task, TaskException, Provider
from freenas.dispatcher.rpc import RpcException, private, accepts, returns, generator
from freenas.utils import query as q


class LocalDatastoreProvider(Provider):
    @private
    @generator
    def discover(self):
        return

    @private
    def get_filesystem_path(self, datastore_id, datastore_path):
        ds = self.datastore.get_by_id('vm.datastores', datastore_id)
        if ds['type'] != 'local':
            raise RpcException(errno.EINVAL, 'Invalid datastore type')

        return os.path.join(q.get(ds, 'properties.path'), datastore_path)

    @private
    def directory_exists(self, datastore_id, datastore_path):
        ds = self.datastore.get_by_id('vm.datastores', datastore_id)
        if ds['type'] != 'local':
            raise RpcException(errno.EINVAL, 'Invalid datastore type')

        return os.path.exists(os.path.join(q.get(ds, 'properties.path'), datastore_path))

    @private
    def get_resources(self, datastore_id):
        return ['system']


class LocalDirectoryCreateTask(Task):
    def run(self, id, path):
        path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, path)
        os.mkdir(path)


class LocalDirectoryDeleteTask(Task):
    def run(self, id, path):
        path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, path)
        shutil.rmtree(path, ignore_errors=True)


class LocalDirectoryRenameTask(Task):
    def run(self, id, old_path, new_path):
        old_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, old_path)
        new_path = self.dispatcher.call_sync('vm.datastore.get_filesystem_path', id, new_path)
        os.rename(old_path, new_path)


def _metadata():
    return {
        'type': 'datastore',
        'driver': 'local',
        'block_devices': False,
        'clones': False,
        'snapshots': False
    }


def _init(dispatcher, plugin):
    plugin.register_schema_definition('vm-datastore-properties-local', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-datastore-local']},
            'path': {'type': 'string'}
        }
    })

    plugin.register_provider('vm.datastore.local', LocalDatastoreProvider)
    plugin.register_task_handler('vm.datastore.local.create_directory', LocalDirectoryCreateTask)
    plugin.register_task_handler('vm.datastore.local.delete_directory', LocalDirectoryDeleteTask)
    plugin.register_task_handler('vm.datastore.local.rename_directory', LocalDirectoryRenameTask)
