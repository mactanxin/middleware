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
import sys
import errno
import socket
import traceback
import logging
import queue
import contextlib
from bsd import setproctitle
from threading import Event
from freenas.dispatcher.client import Client
from freenas.dispatcher.fd import FileDescriptor
from freenas.dispatcher.rpc import RpcService, RpcException, RpcWarning
from freenas.utils import load_module_from_file, configure_logging, serialize_traceback
from datastore import get_datastore
from datastore.config import ConfigStore


def serialize_error(err):
    etype, evalue, tb = sys.exc_info()
    stacktrace = serialize_traceback(tb or traceback.extract_stack())

    ret = {
        'type': type(err).__name__,
        'message': str(err),
        'stacktrace': stacktrace
    }

    if isinstance(err, (RpcException, RpcWarning)):
        ret['code'] = err.code
        ret['message'] = err.message
        if err.extra:
            ret['extra'] = err.extra
    else:
        ret['code'] = errno.EFAULT

    return ret


class DispatcherWrapper(object):
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher

    def run_hook(self, name, args):
        return self.dispatcher.call_sync('task.run_hook', name, args, timeout=300)

    def verify_subtask(self, task, name, args):
        return self.dispatcher.call_sync('task.verify_subtask', name, list(args))

    def run_subtask(self, task, name, args, env=None):
        return self.dispatcher.call_sync('task.run_subtask', name, list(args), env, timeout=60)

    def join_subtasks(self, *tasks):
        return self.dispatcher.call_sync('task.join_subtasks', tasks, timeout=None)

    def abort_subtask(self, id):
        return self.dispatcher.call_sync('task.abort_subtask', id, timeout=60)

    def add_warning(self, warning):
        self.dispatcher.call_sync('task.put_warning', serialize_error(warning))

    def put_progress(self, progress):
        self.dispatcher.call_sync('task.put_progress', progress.__getstate__())

    def register_resource(self, resource, parents):
        self.dispatcher.call_sync('task.register_resource', resource.name, parents)

    def unregister_resource(self, resource):
        self.dispatcher.call_sync('task.unregister_resource', resource)

    def register_task_hook(self, hook, task, condition=None):
        self.dispatcher.call_sync('task.register_task_hook', hook, task, condition)

    def unregister_task_hook(self, hook, task):
        self.dispatcher.call_sync('task.unregister_task_hook', hook, task)

    def task_setenv(self, tid, key, value):
        self.dispatcher.call_sync('task.task_setenv', tid, key, value)

    def __getattr__(self, item):
        if item == 'dispatch_event':
            return self.dispatcher.emit_event

        return getattr(self.dispatcher, item)


class TaskProxyService(RpcService):
    def __init__(self, context):
        self.context = context

    def update_env(self, env):
        os.environ.update(env)

    def get_status(self):
        self.context.running.wait()
        return self.context.instance.get_status()

    def abort(self):
        if not hasattr(self.context.instance, 'abort'):
            raise RpcException(errno.ENOTSUP, 'Abort not supported')

        try:
            self.context.instance.abort()
        except BaseException as err:
            raise RpcException(errno.EFAULT, 'Cannot abort: {0}'.format(str(err)))

    def run(self, task):
        self.context.task.put(task)


class Context(object):
    def __init__(self):
        self.service = TaskProxyService(self)
        self.task = queue.Queue(1)
        self.datastore = None
        self.configstore = None
        self.conn = None
        self.instance = None
        self.module_cache = {}
        self.running = Event()

    def put_status(self, state, result=None, exception=None):
        obj = {
            'status': state,
            'result': None
        }

        if result is not None:
            obj['result'] = result

        if exception is not None:
            obj['error'] = serialize_error(exception)

        self.conn.call_sync('task.put_status', obj)

    def task_progress_handler(self, args):
        if self.instance:
            self.instance.task_progress_handler(args)

    def collect_fds(self, obj):
        if isinstance(obj, dict):
            for v in obj.values():
                if isinstance(v, FileDescriptor):
                    yield v
                else:
                    yield from self.collect_fds(v)

        if isinstance(obj, (list, tuple)):
            for o in obj:
                if isinstance(o, FileDescriptor):
                    yield o
                else:
                    yield from self.collect_fds(o)

    def close_fds(self, fds):
        for i in fds:
            try:
                os.close(i.fd)
            except OSError:
                pass

    def run_task_hooks(self, instance, task, type, **extra_env):
        for hook, props in task['hooks'].get(type, {}).items():
            try:
                if props['condition'] and not props['condition'](*task['args']):
                    continue
            except BaseException as err:
                print(err)
                continue

            instance.join_subtasks(instance.run_subtask(hook, *task['args'], **extra_env))

    def main(self):
        if len(sys.argv) != 2:
            print("Invalid number of arguments", file=sys.stderr)
            sys.exit(errno.EINVAL)

        key = sys.argv[1]
        configure_logging(None, logging.DEBUG)

        self.datastore = get_datastore()
        self.configstore = ConfigStore(self.datastore)
        self.conn = Client()
        self.conn.connect('unix:')
        self.conn.login_service('task.{0}'.format(os.getpid()))
        self.conn.enable_server()
        self.conn.call_sync('management.enable_features', ['streaming_responses'])
        self.conn.rpc.register_service_instance('taskproxy', self.service)
        self.conn.register_event_handler('task.progress', self.task_progress_handler)
        self.conn.call_sync('task.checkin', key)
        setproctitle('task executor (idle)')

        while True:
            try:
                task = self.task.get()
                logging.root.setLevel(self.conn.call_sync('management.get_logging_level'))
                setproctitle('task executor (tid {0})'.format(task['id']))

                if task['debugger']:
                    sys.path.append('/usr/local/lib/dispatcher/pydev')

                    import pydevd
                    host, port = task['debugger']
                    pydevd.settrace(host, port=port, stdoutToServer=True, stderrToServer=True)

                name, _ = os.path.splitext(os.path.basename(task['filename']))
                module = self.module_cache.get(task['filename'])
                if not module:
                    module = load_module_from_file(name, task['filename'])
                    self.module_cache[task['filename']] = module

                setproctitle('task executor (tid {0})'.format(task['id']))
                fds = list(self.collect_fds(task['args']))

                try:
                    dispatcher = DispatcherWrapper(self.conn)
                    self.instance = getattr(module, task['class'])(dispatcher, self.datastore)
                    self.instance.configstore = self.configstore
                    self.instance.user = task['user']
                    self.instance.environment = task['environment']
                    self.running.set()
                    self.run_task_hooks(self.instance, task, 'before')
                    result = self.instance.run(*task['args'])
                    self.run_task_hooks(self.instance, task, 'after', result=result)
                except BaseException as err:
                    print("Task exception: {0}".format(str(err)), file=sys.stderr)
                    traceback.print_exc(file=sys.stderr)

                    if hasattr(self.instance, 'rollback'):
                        self.put_status('ROLLBACK')
                        try:
                            self.instance.rollback(*task['args'])
                        except BaseException as rerr:
                            print("Task exception during rollback: {0}".format(str(rerr)), file=sys.stderr)
                            traceback.print_exc(file=sys.stderr)

                    # Main task is already failed at this point, so ignore hook errors
                    with contextlib.suppress(RpcException):
                        self.run_task_hooks(self.instance, task, 'error', error=serialize_error(err))

                    self.put_status('FAILED', exception=err)
                else:
                    self.put_status('FINISHED', result=result)
                finally:
                    self.close_fds(fds)
                    self.running.clear()

            except RpcException as err:
                print("RPC failed: {0}".format(str(err)), file=sys.stderr)
                print(traceback.format_exc(), flush=True)
                sys.exit(errno.EBADMSG)
            except socket.error as err:
                print("Cannot connect to dispatcher: {0}".format(str(err)), file=sys.stderr)
                sys.exit(errno.ETIMEDOUT)

            if task['debugger']:
                import pydevd
                pydevd.stoptrace()

            setproctitle('task executor (idle)')


if __name__ == '__main__':
    ctx = Context()
    ctx.main()
