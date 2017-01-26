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
import boto3
import botocore
from task import Task, ProgressTask, TaskException, TaskDescription
from freenas.dispatcher.rpc import description
from freenas.utils import normalize


CHUNK_SIZE = 5 * 1024 * 1024
MAX_OBJECT_SIZE = 1024 * 1024 * 1024 * 1024


@description('Lists information about a specific S3 backup')
class BackupS3ListTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Listing information about S3 backup'

    def describe(self, backup):
        return TaskDescription('Listing information about S3 backup')

    def verify(self, backup):
        return []

    def run(self, backup):
        client = open_client(self.dispatcher, backup)
        result = []
        marker = None

        while True:
            ret = client.list_objects_v2(
                Bucket=backup['bucket'],
                Prefix='{0}/'.format(backup['folder']) if backup['folder'] else '',
                **({'ContinuationToken': marker} if marker else {})
            )

            for i in ret.get('Contents', []):
                name, ext = os.path.splitext(i['Key'])
                if ext[1:].isdigit():
                    continue

                result.append({
                    'name': i['Key'],
                    'size': i['Size'],
                    'content_type': None
                })

            if ret['IsTruncated']:
                marker = ret['NextContinuationToken']
                continue

            break

        return result


@description('Initializes a S3 backup')
class BackupS3InitTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Initializing S3 backup'

    def describe(self, backup):
        return TaskDescription('Initializing S3 backup')

    def verify(self, backup):
        return []

    def run(self, backup):
        normalize(backup['properties'], {
            'peer': None,
            'bucket': None,
            'folder': None
        })

        return backup['properties']


@description('Puts new data onto S3 backup')
class BackupS3PutTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Putting new data onto S3 backup'

    def describe(self, backup, name, fd):
        return TaskDescription('Putting new data onto S3 backup {name}', name=name)

    def verify(self, backup, name, fd):
        return []

    def run(self, backup, name, fd):
        client = open_client(self.dispatcher, backup)
        folder = backup['folder'] or ''
        index = 0
        end = False

        try:
            with os.fdopen(fd.fd, 'rb') as f:
                while True:
                    key = os.path.join(folder, suffix(name, index))
                    parts = []
                    idx = 1
                    size = 0
                    mp = client.create_multipart_upload(
                        ACL='authenticated-read',
                        Bucket=backup['bucket'],
                        Key=key
                    )

                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        size += len(chunk)

                        if chunk == b'':
                            end = True
                            break

                        resp = client.upload_part(
                            Bucket=backup['bucket'],
                            Key=key,
                            PartNumber=idx,
                            UploadId=mp['UploadId'],
                            ContentLength=CHUNK_SIZE,
                            Body=chunk
                        )

                        parts.append({
                            'ETag': resp['ETag'],
                            'PartNumber': idx
                        })

                        idx += 1

                        if size + CHUNK_SIZE >= MAX_OBJECT_SIZE:
                            break

                    client.complete_multipart_upload(
                        Bucket=backup['bucket'],
                        Key=key,
                        UploadId=mp['UploadId'],
                        MultipartUpload={
                            'Parts': parts
                        }
                    )

                    index += 1

                    if end:
                        return

                index += 1
        except Exception as err:
            raise TaskException(errno.EFAULT, 'Cannot put object: {0}'.format(str(err)))
        finally:
            pass


@description('Gets data from S3 backup')
class BackupS3GetTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Getting data from S3 backup'

    def describe(self, backup, name, fd):
        return TaskDescription('Getting data from S3 backup {name}', name=name)

    def verify(self, backup, name, fd):
        return []

    def run(self, backup, name, fd):
        client = open_client(self.dispatcher, backup)
        folder = backup['folder'] or ''
        index = 0

        with os.fdopen(fd.fd, 'wb') as f:
            while True:
                try:
                    key = os.path.join(folder, suffix(name, index))
                    obj = client.get_object(
                        Bucket=backup['bucket'],
                        Key=key
                    )
                except botocore.exceptions.ClientError as e:
                    if index != 0:
                        return

                    raise

                while True:
                    chunk = obj['Body'].read(CHUNK_SIZE)
                    if chunk == b'':
                        break

                    f.write(chunk)

                index += 1


def open_client(dispatcher, backup):
    peer = dispatcher.call_sync('peer.query', [('id', '=', backup['peer'])], {'single': True})
    if not peer:
        raise TaskException(errno.ENOENT, 'Cannot find peer {0}'.format(backup['peer']))

    if peer['type'] != 'amazon-s3':
        raise TaskException(errno.EINVAL, 'Invalid peer type: {0}'.format(peer['type']))

    creds = peer['credentials']
    return boto3.client(
        's3',
        aws_access_key_id=creds['access_key'],
        aws_secret_access_key=creds['secret_key'],
        region_name=creds.get('region')
    )


def suffix(name, index):
    if not index:
        return name

    return '{0}.{1}'.format(name, index)


def _depends():
    return ['BackupPlugin']


def _metadata():
    return {
        'type': 'backup',
        'method': 's3'
    }


def _init(dispatcher, plugin):
    plugin.register_schema_definition('BackupS3', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['BackupS3']},
            'peer': {'type': 'string'},
            'bucket': {'type': ['string', 'null']},
            'folder': {'type': ['string', 'null']}
        }
    })

    plugin.register_task_handler('backup.s3.init', BackupS3InitTask)
    plugin.register_task_handler('backup.s3.list', BackupS3ListTask)
    plugin.register_task_handler('backup.s3.get', BackupS3GetTask)
    plugin.register_task_handler('backup.s3.put', BackupS3PutTask)
