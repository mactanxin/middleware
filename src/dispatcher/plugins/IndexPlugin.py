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
import errno
import libzfs
import bsd
from datetime import datetime
from task import Provider, TaskDescription, TaskException, ProgressTask, query
from freenas.dispatcher.rpc import generator, description, accepts, private
from freenas.utils.permissions import get_type, get_unix_permissions


@description("Provides access to the filesystem index")
class IndexProvider(Provider):
    @generator
    @query('FileIndex')
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('fileindex', *(filter or []), **(params or {}))


@description("Generates index of a specified volume")
@accepts(str)
class IndexVolumeTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Indexing a volume"

    def describe(self, volume):
        return TaskDescription("Indexing volume {name}", name=volume)

    def verify(self, volume):
        return ['zpool:{0}'.format(volume)]

    def run(self, volume):
        tasks = []
        for ds in self.dispatcher.call_sync('volume.dataset.query', [('volume', '=', volume)]):
            # Skip zvols and unmounted dataset
            if not ds['mounted']:
                continue

            # Skip .system dataset
            if ds['mountpoint'] == '/var/db/system':
                continue

            # Check if ref snapshot exists
            refsnap = self.dispatcher.call_sync(
                'volume.snapshot.query',
                [('id', '=', '{0}@org.freenas.indexer:ref'.format(ds['id']))],
                {'single': True}
            )

            tasks.append(self.run_subtask(
                'index.generate.dataset.{0}'.format('incremental' if refsnap else 'full'),
                ds['id']
            ))

        self.join_subtasks(*tasks)


@private
@accepts(str)
class IndexDatasetIncrementalTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Indexing a dataset"

    def describe(self, dataset):
        return TaskDescription("Indexing dataset {name}", name=dataset)

    def verify(self, dataset):
        return ['zfs:{0}'.format(dataset)]

    def run(self, dataset):
        self.run_subtask_sync('volume.snapshot.create', {
            'dataset': dataset,
            'name': 'org.freenas.indexer:now',
            'hidden': True
        })

        prev = self.dispatcher.call_sync(
            'volume.snapshot.query',
            [
                ('dataset', '=', dataset),
                ('name', '=', 'org.freenas.indexer:ref')
            ],
            {'single': True}
        )

        if not prev:
            raise TaskException(errno.ENOENT, 'Reference snapshot not found')

        zfs = libzfs.ZFS()
        ds = zfs.get_dataset(dataset)
        if not ds:
            raise TaskException(errno.ENOENT, 'Dataset {0} not found'.format(dataset))

        for rec in ds.diff('{0}@org.freenas.indexer:ref'.format(dataset), '{0}@org.freenas.indexer:now'.format(dataset)):
            collect(self.datastore, rec.path)

        self.run_subtask_sync('volume.snapshot.delete', '{0}@org.freenas.indexer:ref'.format(dataset))
        self.run_subtask_sync('volume.snapshot.update', '{0}@org.freenas.indexer:now'.format(dataset), {
            'name': 'org.freenas.indexer:ref',
        })


@private
@accepts(str)
class IndexDatasetFullTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Indexing a dataset"

    def describe(self, dataset):
        return TaskDescription("Indexing dataset {name}", name=dataset)

    def verify(self, dataset):
        return ['zfs:{0}'.format(dataset)]

    def run(self, dataset):
        mountpoint = self.dispatcher.call_sync('volume.get_dataset_path', dataset)

        # Estimate number of files
        statfs = bsd.statfs(mountpoint)
        total_files = statfs.files - statfs.free_files
        done_files = 0

        for root, dirs, files in os.walk(mountpoint, topdown=True):
            dirs[:] = [dir for dir in dirs if not os.path.ismount(os.path.join(root, dir))]

            for d in dirs:
                path = os.path.join(root, d)
                collect(self.datastore, path)
                done_files += 1
                self.set_progress(done_files / total_files * 100, 'Processing directory {0}'.format(path))

            for f in files:
                path = os.path.join(root, f)
                collect(self.datastore, path)
                done_files += 1

        self.run_subtask_sync('volume.snapshot.create', {
            'dataset': dataset,
            'name': 'org.freenas.indexer:ref',
            'hidden': True
        })


def collect(datastore, path):
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError as err:
        # Can't access the file - delete index entry
        datastore.delete('fileindex', path)
        return

    volume = path.split('/')[2]
    datastore.upsert('fileindex', path, {
        'id': path,
        'volume': volume,
        'type': get_type(st),
        'atime': datetime.utcfromtimestamp(st.st_atime),
        'mtime': datetime.utcfromtimestamp(st.st_mtime),
        'ctime': datetime.utcfromtimestamp(st.st_ctime),
        'uid': st.st_uid,
        'gid': st.st_gid,
        'permissions': get_unix_permissions(st.st_mode)
    })


def _init(dispatcher, plugin):
    plugin.register_schema_definition('FileIndex', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'volume': {'type': 'string'},
            'type': {'type': 'string'},
            'ctime': {'type': 'datetime'},
            'mtime': {'type': 'datetime'},
            'atime': {'type': 'datetime'},
            'size': {'type': 'integer'},
            'uid': {'type': 'integer'},
            'gid': {'type': 'integer'},
            'permissions': {'$ref': 'permissions'}
        }
    })

    plugin.register_provider('index', IndexProvider)
    plugin.register_task_handler('index.generate', IndexVolumeTask)
    plugin.register_task_handler('index.generate.dataset.full', IndexDatasetFullTask)
    plugin.register_task_handler('index.generate.dataset.incremental', IndexDatasetIncrementalTask)
