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
import bsd
import errno
from lib.system import system
from task import Task, TaskException, Provider
from freenas.dispatcher.rpc import RpcException, private, accepts, returns, generator


class NFSDatastoreProvider(Provider):
    @private
    @generator
    def discover(self):
        return

    @private
    def get_filesystem_path(self, datastore_id, datastore_path):
        ds = self.datastore.get_by_id('vm.datastores', datastore_id)
        if ds['type'] != 'nfs':
            raise RpcException(errno.EINVAL, 'Invalid datastore type')

        return os.path.join('/nfs', ds['name'], datastore_path)

    @private
    def directory_exists(self, datastore_id, datastore_path):
        ds = self.datastore.get_by_id('vm.datastores', datastore_id)
        if ds['type'] != 'nfs':
            raise RpcException(errno.EINVAL, 'Invalid datastore type')

        return os.path.exists(os.path.join('/nfs', ds['name'], datastore_path))

    @private
    def get_resources(self, datastore_id):
        return ['system']


class NFSDatastoreCreateTask(Task):
    def verify(self, datastore):
        return ['system']

    def run(self, datastore):
        mount(datastore['name'], datastore['properties'])


class NFSDatastoreUpdateTask(Task):
    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        pass


class NFSDatastoreDeleteTask(Task):
    def verify(self, id):
        return ['system']

    def run(self, id):
        ds = self.datastore.get_by_id('vm.datastores', id)
        umount(ds['name'])


def _metadata():
    return {
        'type': 'datastore',
        'driver': 'nfs',
        'block_devices': False,
        'clones': False,
        'snapshots': False
    }


def mount(name, properties):
    # XXX: Couldn't figure out how to do that with py-bsd's nmount
    system('/sbin/mount_nfs', '{address}:{path}'.format(**properties), os.path.join('/nfs', name))


def umount(name):
    bsd.unmount(os.path.join('/nfs', name))


def _depends():
    return ['LocalDatastorePlugin']


def _init(dispatcher, plugin):
    plugin.register_schema_definition('vm-datastore-nfs-version', {
        'type': 'string',
        'enum': ['NFSV3', 'NFSV4']
    })

    plugin.register_schema_definition('vm-datastore-properties-nfs', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-datastore-nfs']},
            'address': {'type': 'string'},
            'path': {'type': 'string'},
            'version': {'$ref': 'vm-datastore-nfs-version'}
        }
    })

    plugin.register_provider('vm.datastore.nfs', NFSDatastoreProvider)
    plugin.register_task_handler('vm.datastore.nfs.create', NFSDatastoreCreateTask)
    plugin.register_task_handler('vm.datastore.nfs.update', NFSDatastoreUpdateTask)
    plugin.register_task_handler('vm.datastore.nfs.delete', NFSDatastoreDeleteTask)
    plugin.register_task_alias('vm.datastore.nfs.create_directory', 'vm.datastore.local.create_directory')
    plugin.register_task_alias('vm.datastore.nfs.delete_directory', 'vm.datastore.local.delete_directory')

    if not os.path.isdir('/nfs'):
        os.mkdir('/nfs')

    def init(args):
        for i in dispatcher.datastore.query('vm.datastores', ('type', '=', 'nfs')):
            mount(i['name'], i['properties'])

    dispatcher.register_event_handler_once('network.changed', init)
