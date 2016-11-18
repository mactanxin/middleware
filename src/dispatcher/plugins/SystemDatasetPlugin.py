#+
# Copyright 2015 iXsystems, Inc.
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
import uuid
import logging
import shutil
import time
import tempfile
import libzfs
from resources import Resource
from freenas.dispatcher.rpc import RpcException, accepts, returns, description, private
from freenas.dispatcher.rpc import SchemaHelper as h
from task import Task, Provider, TaskException, TaskDescription
from freenas.utils.copytree import copytree


SYSTEM_DIR = '/var/db/system'
logger = logging.getLogger('SystemDataset')


def link_directories(dispatcher):
    for name, d in dispatcher.configstore.get('system.dataset.layout').items():
        target = dispatcher.call_sync('system_dataset.request_directory', name)
        if 'link' in d:
            if not os.path.islink(d['link']) or not os.readlink(d['link']) == target:
                if os.path.exists(d['link']):
                    shutil.move(d['link'], d['link'] + '.{0}.bak'.format(int(time.time())))
                os.symlink(target, d['link'])

        if hasattr(d, 'owner'):
            user = dispatcher.call_sync('user.query', [('username', '=', d['owner'])], {'single': True})
            group = dispatcher.call_sync('group.query', [('name', '=', d['group'])], {'single': True})
            if user and group:
                os.chown(target, user['uid'], group['gid'])

        for cname, c in d.get('children', {}).items():
            try:
                os.mkdir(os.path.join(target, cname))
            except OSError as err:
                if err.errno != errno.EEXIST:
                    logger.warning('Cannot create skeleton directory {0}: {1}'.format(
                        os.path.join(target, cname),
                        str(err))
                    )

            if 'owner' in c:
                user = dispatcher.call_sync('user.query', [('username', '=', c['owner'])], {'single': True})
                group = dispatcher.call_sync('group.query', [('name', '=', c['group'])], {'single': True})
                if user and group:
                    os.chown(os.path.join(target, cname), user['uid'], group['gid'])


def create_system_dataset(dispatcher, dsid, pool):
    logger.warning('Creating system dataset on pool {0}'.format(pool))
    zfs = libzfs.ZFS()
    pool = zfs.get(pool)

    try:
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))
    except libzfs.ZFSException:
        pool.create('{0}/.system-{1}'.format(pool.name, dsid), {
            'mountpoint': 'none',
            'sharenfs': 'off'
        })
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))

    try:
        ds.properties['canmount'].value = 'noauto'
        ds.properties['mountpoint'].value = SYSTEM_DIR
    except libzfs.ZFSException as err:
        logger.warning('Cannot set properties on .system dataset: {0}'.format(str(err)))


def remove_system_dataset(dispatcher, dsid, pool):
    logger.warning('Removing system dataset from pool {0}'.format(pool))
    zfs = libzfs.ZFS()
    pool = zfs.get(pool)
    try:
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))
        ds.umount(force=True)
        ds.delete()
    except libzfs.ZFSException:
        pass


def mount_system_dataset(dispatcher, dsid, pool, path):
    logger.warning('Mounting system dataset from pool {0} on {1}'.format(pool, path))
    zfs = libzfs.ZFS()
    pool = zfs.get(pool)
    try:
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))
        if ds.mountpoint:
            logger.warning('.system dataset already mounted')
            return

        ds.properties['mountpoint'].value = path
        ds.mount()
    except libzfs.ZFSException as err:
        logger.error('Cannot mount .system dataset on pool {0}: {1}'.format(pool.name, str(err)))
        raise err


def umount_system_dataset(dispatcher, dsid, pool):
    zfs = libzfs.ZFS()
    pool = zfs.get(pool)
    try:
        ds = zfs.get_dataset('{0}/.system-{1}'.format(pool.name, dsid))
        ds.umount(force=True)
        return
    except libzfs.ZFSException as err:
        logger.error('Cannot unmount .system dataset on pool {0}: {1}'.format(pool.name, str(err)))


def move_system_dataset(dispatcher, dsid, services, src_pool, dst_pool):
    logger.warning('Migrating system dataset from pool {0} to {1}'.format(src_pool, dst_pool))
    tmpath = tempfile.mkdtemp()
    create_system_dataset(dispatcher, dsid, dst_pool)
    mount_system_dataset(dispatcher, dsid, dst_pool, tmpath)

    for s in services:
        try:
            dispatcher.call_sync('service.ensure_stopped', s)
        except RpcException as err:
            logger.warning('Failed to stop {0} service: {1}'.format(s, err))

    dispatcher.call_sync('management.stop_logdb')

    try:
        copytree(SYSTEM_DIR, tmpath)
    except shutil.Error as err:
        logger.warning('Following errors were encountered during migration:')
        for i in err.args[0]:
            logger.warning('{0} -> {1}: {2}'.format(*i[0]))

    umount_system_dataset(dispatcher, dsid, dst_pool)
    umount_system_dataset(dispatcher, dsid, src_pool)
    mount_system_dataset(dispatcher, dsid, dst_pool, SYSTEM_DIR)
    remove_system_dataset(dispatcher, dsid, src_pool)

    dispatcher.call_sync('management.start_logdb')

    for s in services:
        try:
            dispatcher.call_sync('service.ensure_started', s, timeout=20)
        except RpcException as err:
            logger.warning('Failed to start {0} service: {1}'.format(s, err))


def import_system_dataset(dispatcher, services, src_pool, old_pool, old_id):
    logger.warning('Importing system dataset from pool {0}'.format(src_pool))

    system_dataset = dispatcher.call_sync(
        'zfs.dataset.query',
        [('pool', '=', src_pool), ('name', '~', '.system')],
        {'single': True}
    )
    id = system_dataset['name'][-8:]

    for s in services:
        dispatcher.call_sync('service.ensure_stopped', s)

    dispatcher.call_sync('management.stop_logdb')

    umount_system_dataset(dispatcher, old_id, old_pool)
    mount_system_dataset(dispatcher, id, src_pool, SYSTEM_DIR)
    remove_system_dataset(dispatcher, old_id, old_pool)

    dispatcher.call_sync('management.start_logdb')

    for s in services:
        dispatcher.call_sync('service.ensure_started', s, timeout=20)

    return id


@description('Provides information about System Dataset')
class SystemDatasetProvider(Provider):
    @private
    @description("Initializes the .system dataset")
    @accepts()
    def init(self):
        pool = self.configstore.get('system.dataset.pool')
        dsid = self.configstore.get('system.dataset.id')
        create_system_dataset(self.dispatcher, dsid, pool)
        mount_system_dataset(self.dispatcher, dsid, pool, SYSTEM_DIR)
        link_directories(self.dispatcher)

    @private
    @description("Creates directory in .system dataset and returns reference to it")
    @accepts(str)
    @returns(str)
    def request_directory(self, name):
        path = os.path.join(SYSTEM_DIR, name)
        if os.path.exists(path):
            if os.path.isdir(path):
                return path

            raise RpcException(errno.EPERM, 'Cannot grant directory {0}'.format(name))

        os.mkdir(path)
        return path

    @description("Returns current .system dataset parameters")
    @returns(h.object())
    def status(self):
        return {
            'id': self.configstore.get('system.dataset.id'),
            'pool': self.configstore.get('system.dataset.pool')
        }


@description("Updates .system dataset configuration")
@accepts(str)
class SystemDatasetConfigure(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating .system dataset configuration'

    def describe(self, pool):
        return TaskDescription('Updating .system dataset configuration')

    def verify(self, pool):
        return ['root']

    def run(self, pool):
        status = self.dispatcher.call_sync('system_dataset.status')
        services = self.configstore.get('system.dataset.services')
        restart = [s for s in services if self.configstore.get('service.{0}.enable'.format(s))]

        logger.warning('Services to be restarted: {0}'.format(', '.join(restart)))

        if status['pool'] != pool:
            move_system_dataset(
                self.dispatcher,
                self.configstore.get('system.dataset.id'),
                restart,
                status['pool'],
                pool
            )

        self.configstore.set('system.dataset.pool', pool)


@private
@description("Imports .system dataset from a volume")
@accepts(str)
class SystemDatasetImport(Task):
    @classmethod
    def early_describe(cls):
        return 'Importing .system dataset from volume'

    def describe(self, pool):
        return TaskDescription('Importing .system dataset from volume {name}', name=pool)

    def verify(self, pool):
        return ['root']

    def run(self, pool):
        if not self.dispatcher.call_sync('zfs.dataset.query', [('pool', '=', pool), ('name', '~', '.system')], {'single': True}):
            raise TaskException(errno.ENOENT, 'System dataset not found on pool {0}'.format(pool))

        status = self.dispatcher.call_sync('system_dataset.status')
        services = self.configstore.get('system.dataset.services')
        restart = [s for s in services if self.configstore.get('service.{0}.enable'.format(s))]

        logger.warning('Services to be restarted: {0}'.format(', '.join(restart)))

        if status['pool'] != pool:
            new_id = import_system_dataset(
                self.dispatcher,
                restart,
                pool,
                status['pool'],
                self.configstore.get('system.dataset.id')
            )

            self.configstore.set('system.dataset.pool', pool)
            self.configstore.set('system.dataset.id', new_id)
            logger.info('New system dataset ID: {0}'.format(new_id))


def _depends():
    return ['ZfsPlugin', 'VolumePlugin']


def _init(dispatcher, plugin):
    last_sysds_name = ''

    def on_volumes_changed(args):
        if args['operation'] == 'create':
            pass

    def on_datasets_changed(args):
        nonlocal last_sysds_name

        if args['operation'] != 'update':
            return

        for i in args['entities']:
            if '.system-' in i['id']:
                if i['mountpoint'] == SYSTEM_DIR:
                    if i['id'] != last_sysds_name:
                        dispatcher.update_resource(
                            'system-dataset',
                            new_parents=['zfs:{0}'.format(i['id'])]
                        )
                        last_sysds_name = i['id']
                        return

    def volume_pre_destroy(args):
        # Evacuate .system dataset from the pool
        if dispatcher.configstore.get('system.dataset.pool') == args['name']:
            dispatcher.call_task_sync('system_dataset.migrate', 'freenas-boot')

        return True

    if not dispatcher.configstore.get('system.dataset.id'):
        dsid = uuid.uuid4().hex[:8]
        dispatcher.configstore.set('system.dataset.id', dsid)
        logger.info('New system dataset ID: {0}'.format(dsid))

    pool = dispatcher.configstore.get('system.dataset.pool')
    dsid = dispatcher.configstore.get('system.dataset.id')
    dispatcher.register_resource(
        Resource('system-dataset'),
        parents=['zfs:{0}/.system-{1}'.format(pool, dsid)]
    )
    last_sysds_name = '{0}/.system-{1}'.format(pool, dsid)

    plugin.register_event_handler('volume.changed', on_volumes_changed)
    plugin.register_event_handler('entity-subscriber.zfs.dataset.changed', on_datasets_changed)
    plugin.attach_hook('volume.pre_destroy', volume_pre_destroy)
    plugin.attach_hook('volume.pre_detach', volume_pre_destroy)
    plugin.attach_hook('volume.pre_rename', volume_pre_destroy)
    plugin.register_provider('system_dataset', SystemDatasetProvider)
    plugin.register_task_handler('system_dataset.migrate', SystemDatasetConfigure)
    plugin.register_task_handler('system_dataset.import', SystemDatasetImport)

    plugin.register_hook('system_dataset.pre_detach')
    plugin.register_hook('system_dataset.pre_attach')
