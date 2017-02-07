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
import threading
import uuid
import errno
import time
import logging
from task import Task, Provider, TaskDescription, TaskWarning, ProgressTask
from freenas.dispatcher.fd import FileDescriptor
from freenas.dispatcher.rpc import RpcException, description, generator, accepts
from freenas.utils import query as q
from freenas.utils.lazy import lazy


logger = logging.getLogger('TestPlugin')


@description("Test Rpc Provider")
class TestProvider(Provider):
    @generator
    def stream(self, count=10):
        for i in range(0, count):
            yield {"id": 1, "value": "{0} bottles of beer on the wall".format(i)}

    @generator
    def wrapped_stream(self, count=10):
        return self.dispatcher.call_sync('test.stream', count)

    def sleep(self, n):
        time.sleep(n)
        return 'done'

    def rpcerror(self):
        raise RpcException(errno.EINVAL, 'Testing if parameter', 'This is in the extra paramaeter')

    def lazy_query(self, filter=None, params=None):
        def extend(obj):
            def doit():
                time.sleep(1)
                return 'I am so slow: {0}'.format(obj['id'])

            obj['fast_value'] = obj['id'] * 5
            obj['slow_value'] = lazy(doit)
            return obj

        gen = ({'id': i} for i in range(0, 10))
        return q.query(gen, *(filter or []), callback=extend, **(params or {}))


@description('Downloads tests')
class TestDownloadTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Downloading tests'

    def describe(self):
        return TaskDescription('Downloading tests')

    def verify(self):
        return []

    def run(self):
        rfd, wfd = os.pipe()

        def feed():
            with os.fdopen(wfd, 'w') as f:
                for i in range(0, 100):
                    f.write(str(uuid.uuid4()) + '\n')

        t = threading.Thread(target=feed)
        t.start()
        url = self.run_subtask_sync(
            'file.prepare_url_download', FileDescriptor(rfd)
        )
        t.join(timeout=1)

        return url


@accepts(FileDescriptor)
@description('Download on the fly test task')
class DownloadOnTheFlyTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading random text and saving to file specified'

    def descrive(self, fd):
        return TaskDescription('Downloading random text and saving to file')

    def verify(self, fd):
        return []

    def run(self, fd):
        with os.fdopen(fd.fd, 'w') as f:
            for i in range(0, 1000):
                self.set_progress(i / 10.0, 'Writing data to the file being downloaded')
                f.write(str(uuid.uuid4()) + '\n')


class TestWarningsTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Task Warning Tests'

    def describe(self):
        return TaskDescription('Testing Task Warnings')

    def verify(self):
        return []

    def run(self):
        self.add_warning(TaskWarning(errno.EBUSY, 'Warning 1'))
        self.add_warning(TaskWarning(errno.ENXIO, 'Warning 2'))
        self.add_warning(
            TaskWarning(errno.EINVAL, 'Warning 3 with extra payload', extra={'hello': 'world'})
        )


class ProgressTestTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Progress task test'

    def describe(self):
        return TaskDescription('Progress task test')

    def verify(self):
        return []

    def run(self):
        for i in range(0, 100):
            time.sleep(0.1)
            self.set_progress(i, 'fiddling')


class FailingTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Failing task test'

    def describe(self):
        return TaskDescription('Failing task test')

    def verify(self):
        return []

    def run(self):
        time.sleep(1)
        os.abort()


class UnreasonableErrorTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Task raising unreasonable error test'

    def describe(self):
        return TaskDescription('Task raising unreasonable error test')

    def verify(self):
        return []

    def run(self):
        raise ZeroDivisionError('universe explodes')


class TestAbortTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Abort task test'

    def describe(self):
        return TaskDescription('Abort task test')

    def verify(self):
        return []

    def run(self):
        self.run_subtask_sync('test.abort.subtask')


class TestAbortSubtask(Task):
    @classmethod
    def early_describe(cls):
        return 'Abort subtask test'

    def describe(self):
        return TaskDescription('Abort subtask test')

    def verify(self):
        return []

    def run(self):
        time.sleep(20)


def _init(dispatcher, plugin):
    plugin.register_provider("test", TestProvider)
    plugin.register_task_handler('test.test_download', TestDownloadTask)
    plugin.register_task_handler('test.ontheflydownload', DownloadOnTheFlyTask)
    plugin.register_task_handler('test.test_warnings', TestWarningsTask)
    plugin.register_task_handler('test.progress', ProgressTestTask)
    plugin.register_task_handler('test.failing', FailingTask)
    plugin.register_task_handler('test.unreasonable_error', UnreasonableErrorTask)
    plugin.register_task_handler('test.abort', TestAbortTask)
    plugin.register_task_handler('test.abort.subtask', TestAbortSubtask)
