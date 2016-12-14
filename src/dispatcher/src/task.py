#+
# Copyright 2014 iXsystems, Inc.
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

import copy
import errno
import logging
from freenas.dispatcher.rpc import RpcService, RpcException, RpcWarning
from datastore.config import ConfigStore
from threading import RLock
import collections


class TaskState(object):
    CREATED = 'CREATED'
    WAITING = 'WAITING'
    EXECUTING = 'EXECUTING'
    ROLLBACK = 'ROLLBACK'
    FINISHED = 'FINISHED'
    FAILED = 'FAILED'
    ABORTED = 'ABORTED'


class Task(object):
    SUCCESS = (0, "Success")

    def __init__(self, dispatcher, datastore):
        self.dispatcher = dispatcher
        self.datastore = datastore
        self.configstore = ConfigStore(datastore)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.subtasks = []
        self.progress_callbacks = {}
        self.user = None
        self.environment = {}
        self.do_abort = False
        self.rlock = RLock()

    def task_progress_handler(self, args):
        with self.rlock:
            id = args['id']
            try:
                self.progress_callbacks[id](
                    args['percentage'],
                    args['message']
                )
            except:
                # ignore
                pass

    @classmethod
    def _get_metadata(cls):
        return {
            'description': getattr(cls, 'description', None),
            'schema': getattr(cls, 'params_schema', None),
            'abortable': True if (hasattr(cls, 'abort') and isinstance(cls.abort, collections.Callable)) else False,
            'private': getattr(cls, 'private', False),
            'metadata': getattr(cls, 'metadata', None)
        }

    @classmethod
    def early_describe(cls):
        return cls.__name__

    def describe(self, *args, **kwargs):
        return

    def put_progress(self, progress):
        self.dispatcher.put_progress(progress)

    def add_warning(self, warning):
        return self.dispatcher.add_warning(warning)

    def verify_subtask(self, classname, *args):
        with self.rlock:
            return self.dispatcher.verify_subtask(self, classname, args)

    def run_subtask(self, classname, *args, **kwargs):
        with self.rlock:
            callback = kwargs.pop('progress_callback', None)
            environment = kwargs.pop('environment', None)
            tid = self.dispatcher.run_subtask(self, classname, args, environment)
            if callback:
                self.progress_callbacks[tid] = callback

            self.subtasks.append(tid)
            return tid

    def join_subtasks(self, *tasks):
        try:
            return self.dispatcher.join_subtasks(*tasks)
        except:
            if self.do_abort:
                raise TaskAbortException(errno.EINTR, 'Aborted')

            raise
        finally:
            with self.rlock:
                for t in tasks:
                    self.subtasks.remove(t)
                    self.progress_callbacks.pop(t, None)

    def run_subtask_sync(self, classname, *args, **kwargs):
        ret, = self.join_subtasks(self.run_subtask(classname, *args, **kwargs))
        return ret

    def abort_subtask(self, id):
        return self.dispatcher.abort_subtask(id)

    def abort_subtasks(self):
        with self.rlock:
            self.do_abort = True
            for t in self.subtasks:
                self.abort_subtask(t)

    def chain(self, task, *args):
        self.dispatcher.balancer.submit(task, *args)

    def verify(self, *args, **kwargs):
        return []

    def run(self, *args, **kwargs):
        raise NotImplementedError()


class ProgressTask(Task):
    def __init__(self, dispatcher, datastore):
        super(ProgressTask, self).__init__(dispatcher, datastore)
        self.progress = 0
        self.message = 'EXECUTING...'

    def set_progress(self, percentage, message=None, extra=None):
        self.put_progress(TaskStatus(percentage, message, extra))

    def chunk_progress(self, start_percentage, end_percentage, message, child_percentage, child_message=None, extra=None):
        self.set_progress(
            start_percentage + ((end_percentage - start_percentage) * (child_percentage / 100)),
            '{0} {1}'.format(message, child_message),
            extra
        )


class TaskException(RpcException):
    pass


class TaskAbortException(TaskException):
    pass


class TaskWarning(RpcWarning):
    pass


class VerifyException(TaskException):
    pass


class ValidationException(VerifyException):
    def __init__(self, errors=None, extra=None, **kwargs):
        super(ValidationException, self).__init__(errno.EBADMSG, 'Validation failed', extra=[])

        if errors:
            for path, code, message in errors:
                self.extra.append({
                    'path': list(path),
                    'code': code,
                    'message': message
                })

        if extra:
            self.extra = extra

    def add(self, path, message, code=errno.EINVAL):
        self.extra.append({
            'path': list(path),
            'code': code,
            'message': message
        })

    def propagate(self, other, src_path, dst_path):
        if other.extra:
            for err in other.extra:
                if err['path'][:len(src_path)] == src_path:
                    new_err = copy.deepcopy(err)
                    new_err['path'] = dst_path + err['path'][len(src_path):]
                    self.extra.append(new_err)
        else:
            self.extra.append({
                'path': dst_path,
                'message': other.message,
                'code': other.code
            })

    def __bool__(self):
        return bool(self.extra)


class TaskStatus(object):
    def __init__(self, percentage, message=None, extra=None):
        self.percentage = percentage
        self.message = message
        self.extra = extra

    def __getstate__(self):
        return {
            'percentage': self.percentage,
            'message': self.message,
            'extra': self.extra
        }

    def __setstate__(self, obj):
        self.percentage = obj['percentage']
        self.message = obj['message']
        self.extra = obj['extra']


class TaskDescription(object):
    def __init__(self, fmt, **kwargs):
        self.kwargs = kwargs
        self.fmt = fmt

    def __str__(self):
        try:
            return self.fmt.format(**self.kwargs)
        except (KeyError, IndexError):
            return self.fmt

    def __getstate__(self):
        return {
            'message': str(self),
            'name': self.kwargs.get('name'),
            'format': {
                'string': self.fmt,
                'args': self.kwargs
            }
        }


class Provider(RpcService):
    def initialize(self, context):
        self.dispatcher = context.dispatcher
        self.datastore = self.dispatcher.datastore
        self.configstore = self.dispatcher.configstore


def metadata(**d):
    def wrapped(fn):
        fn.metadata = d

    return wrapped


def query(result_type):
    def wrapped(fn):
        fn.params_schema = [
            {
                'title': 'filter',
                'type': 'array',
                'items': {
                    'type': 'array',
                    'minItems': 2,
                    'maxItems': 4
                }
            },
            {
                'title': 'options',
                'type': 'object',
                'properties': {
                    'sort': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    },
                    'limit': {'type': 'integer'},
                    'offset': {'type': 'integer'},
                    'single': {'type': 'boolean'},
                    'count': {'type': 'boolean'}
                }
            }
        ]

        fn.result_schema = {
            'anyOf': [
                {
                    'type': 'array',
                    'items': {'$ref': result_type}
                },
                {
                    'type': 'integer'
                },
                {
                    '$ref': result_type
                }
            ]
        }

        return fn

    return wrapped
