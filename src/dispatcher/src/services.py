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

import sys
import gc
import traceback
import errno
import subprocess
import gevent
import logging
import tracemalloc
from resources import Resource
from gevent.event import Event
from gevent.lock import Semaphore
from gevent.backdoor import BackdoorServer
from freenas.dispatcher.rpc import RpcService, RpcException, pass_sender, private, generator, unauthenticated
from auth import ShellToken
from task import TaskState, query
from freenas.utils import first_or_default
from freenas.utils.trace_logger import TRACE


class ManagementService(RpcService):
    def initialize(self, context):
        self.context = context
        self.dispatcher = context.dispatcher

    def status(self):
        return {
            'started-at': self.dispatcher.started_at,
            'connected-clients': sum([len(s.connections) for s in self.dispatcher.ws_servers])
        }

    def ping(self):
        return 'pong'

    def reload_plugins(self):
        self.dispatcher.reload_plugins()

    def restart(self):
        pass

    def get_event_sources(self):
        return list(self.dispatcher.event_sources.keys())

    def get_plugin_names(self):
        return list(self.dispatcher.plugins.keys())

    def get_connected_clients(self):
        return [
            inner
            for outter in [list(s.connections) for s in self.dispatcher.ws_servers]
            for inner in outter
        ]

    def wait_ready(self):
        return self.dispatcher.ready.wait()

    @pass_sender
    def kick_session(self, session_id, sender):
        session = first_or_default(
            lambda s: s.session_id == session_id,
            self.dispatcher.ws_server.connections)

        if not session:
            raise RpcException(errno.ENOENT, 'Session {0} not found'.format(session_id))

        session.logout('Kicked out by {0}'.format(sender.user.name))

    @pass_sender
    @unauthenticated
    def get_sender_address(self, sender):
        return sender.client_address

    @pass_sender
    def enable_features(self, features, sender):
        for i in features:
            try:
                sender.enable_feature(i)
            except ValueError:
                raise RpcException(errno.EINVAL, 'Invalid feature {0}'.format(i))

    @pass_sender
    def get_enabled_features(self, sender):
        return list(sender.enabled_features)

    @pass_sender
    def get_available_features(self, sender):
        return list(self.dispatcher.features)

    def die_you_gravy_sucking_pig_dog(self):
        self.dispatcher.die()

    def start_logdb(self):
        self.dispatcher.start_logdb()

    def stop_logdb(self):
        self.dispatcher.stop_logdb()

    def collect_debug(self, plugin_name):
        plugin = self.dispatcher.plugins.get(plugin_name)
        result = []
        if not plugin:
            raise RpcException(errno.ENOENT, 'Plugin not found')

        for hook in plugin.registers['debug']:
            result.extend(c.__getstate__() for c in hook(self.dispatcher))

        return result

    def set_logging_level(self, level):
        self.dispatcher.set_syslog_level(level)

    def get_logging_level(self):
        level = logging.getLogger().getEffectiveLevel()
        if level == TRACE:
            return 'TRACE'
        else:
            return logging.getLevelName(level)


class DebugService(RpcService):
    def __init__(self):
        super(DebugService, self).__init__()
        self.dispatcher = None
        self.backdoor_server = None

    def initialize(self, context):
        self.dispatcher = context.dispatcher

    @private
    def dump_stacks(self):
        from greenlet import greenlet

        # If greenlet is present, let's dump each greenlet stack
        dump = []
        for ob in gc.get_objects():
            if not isinstance(ob, greenlet):
                continue
            if not ob:
                continue   # not running anymore or not started

            dump.append(''.join(traceback.format_stack(ob.gr_frame)))

        return dump

    @private
    def attach(self, host, port):
        sys.path.append('/usr/local/lib/dispatcher/pydev')

        import pydevd
        pydevd.settrace(host, port=port, stdoutToServer=True, stderrToServer=True)

    @private
    def detach(self):
        import pydevd
        pydevd.stoptrace()

    @private
    def set_tasks_debug(self, host, port, tasks=None):
        self.dispatcher.balancer.debugger = (host, port)
        self.dispatcher.balancer.debugged_tasks = tasks or ['*']

    @private
    def cancel_tasks_debug(self):
        self.dispatcher.balancer.debugger = None
        self.dispatcher.balancer.debugged_tasks = None

    @private
    def start_backdoor(self):
        self.backdoor_server = BackdoorServer(
            ('127.0.0.1', 9999),
            banner='DebugService backdoor server',
            locals={
                'dispatcher': self.dispatcher
            }
        )

        gevent.spawn(self.backdoor_server.serve_forever)

    @private
    def stop_backdoor(self):
        if self.backdoor_server:
            self.backdoor_server.close()
            self.backdoor_server = None

    @private
    def start_tracemalloc(self):
        tracemalloc.start()

    @private
    def stop_tracemalloc(self):
        tracemalloc.stop()

    @private
    def snapshot_tracemalloc(self):
        snap = tracemalloc.take_snapshot()
        return [str(i) for i in snap.statistics('lineno')[:100]]


class EventService(RpcService):
    def initialize(self, context):
        self.__datastore = context.dispatcher.datastore
        self.__dispatcher = context.dispatcher

    def query(self, filter=None, params=None):
        return self.__datastore.query('events', *(filter or []), **(params or {}))

    @pass_sender
    def get_my_subscriptions(self, sender):
        return list(sender.event_masks)

    @private
    def suspend(self):
        self.__dispatcher.event_delivery_lock.acquire()

    @private
    def resume(self):
        self.__dispatcher.event_delivery_lock.release()


class PluginService(RpcService):
    class RemoteServiceWrapper(RpcService):
        def __init__(self, connection, name):
            self.connection = connection
            self.service_name = name
            self.resumed = Event()

        def get_metadata(self):
            return self.connection.call_sync(self.service_name + '.get_metadata')

        def enumerate_methods(self):
            return list(self.connection.call_sync(self.service_name + '.enumerate_methods'))

        def __getattr__(self, name):
            @generator
            def call_wrapped(*args):
                self.resumed.wait()
                return self.connection.call_sync(
                    '.'.join([self.service_name, name]),
                    *args,
                    timeout=60
                )

            return call_wrapped

    def __client_disconnected(self, args):
        for name, svc in list(self.services.items()):
            if args['address'] == svc.connection.client_address:
                self.unregister_service(name, svc.connection)

        for name, conn in list(self.schemas.items()):
            if args['address'] == conn.client_address:
                self.unregister_schema(name, conn)

        for name, conn in list(self.event_types.items()):
            if args['address'] == conn.client_address:
                self.unregister_event_type(name)

    def initialize(self, context):
        self.services = {}
        self.schemas = {}
        self.events = {}
        self.event_types = {}
        self.__dispatcher = context.dispatcher
        self.__dispatcher.register_event_handler('server.client_disconnected', self.__client_disconnected)
        self.__dispatcher.register_event_type('plugin.service_unregistered')
        self.__dispatcher.register_event_type('plugin.service_registered')
        self.__dispatcher.register_event_type('plugin.service_resume')

    @pass_sender
    def register_service(self, name, sender):
        wrapper = self.RemoteServiceWrapper(sender, name)
        self.services[name] = wrapper
        self.__dispatcher.rpc.register_service_instance(name, wrapper)
        self.__dispatcher.dispatch_event('plugin.service_registered', {
            'address': sender.client_address,
            'service-name': name,
            'description': "Service {0} registered".format(name)
        })

        if name in list(self.events.keys()):
            self.events[name].set()

    @pass_sender
    def unregister_service(self, name, sender):
        if name not in list(self.services.keys()):
            raise RpcException(errno.ENOENT, 'Service not found')

        svc = self.services[name]
        if svc.connection != sender:
            raise RpcException(errno.EPERM, 'Permission denied')

        self.__dispatcher.rpc.unregister_service(name)
        self.__dispatcher.dispatch_event('plugin.service_unregistered', {
            'address': sender.client_address,
            'service-name': name,
            'description': "Service {0} unregistered".format(name)
        })

        del self.services[name]

    @pass_sender
    def resume_service(self, name, sender):
        if name not in list(self.services.keys()):
            raise RpcException(errno.ENOENT, 'Service not found')

        svc = self.services[name]
        if svc.connection != sender:
            raise RpcException(errno.EPERM, 'Permission denied')

        svc.resumed.set()

        self.__dispatcher.dispatch_event('plugin.service_resume', {
            'name': name,
        })

    @pass_sender
    def register_schema(self, name, schema, sender):
        self.schemas[name] = sender
        self.__dispatcher.register_schema_definition(name, schema)

    @pass_sender
    def unregister_schema(self, name, sender):
        if name not in list(self.schemas.keys()):
            raise RpcException(errno.ENOENT, 'Schema not found')

        conn = self.schemas[name]
        if conn != sender:
            raise RpcException(errno.EPERM, 'Permission denied')

        self.__dispatcher.unregister_schema_definition(name)
        del self.schemas[name]

    @pass_sender
    def register_event_type(self, service, event, sender):
        wrapper = self.services[service]
        self.event_types[event] = sender
        self.__dispatcher.register_event_type(event, wrapper)

    @pass_sender
    def unregister_event_type(self, event):
        self.__dispatcher.unregister_event_type(event)
        del self.event_types[event]

    def wait_for_service(self, name, timeout=None):
        if name in list(self.services.keys()):
            return

        self.events[name] = Event()
        self.events[name].wait(timeout)
        del self.events[name]


class TaskService(RpcService):
    def initialize(self, context):
        self.__dispatcher = context.dispatcher
        self.__datastore = context.dispatcher.datastore
        self.__balancer = context.dispatcher.balancer

    @pass_sender
    def submit(self, name, args, sender):
        tid = self.__balancer.submit(name, args, sender)
        return tid

    @pass_sender
    def submit_with_env(self, name, args, env, sender):
        tid = self.__balancer.submit(name, args, sender, env)
        return tid

    @pass_sender
    def submit_with_upload(self, task_name, args, sender):
        return self.__balancer.submit_with_upload(task_name, args, sender)

    @pass_sender
    def submit_with_download(self, task_name, args, sender):
        tid, url_list = self.__balancer.submit_with_download(task_name, args, sender)
        return tid, url_list

    def status(self, id):
        t = self.__datastore.get_by_id('tasks', id)
        task = self.__balancer.get_task(id)

        if task and task.progress:
            t['progress'] = task.progress.__getstate__()

        return t

    def wait(self, id):
        task = self.__balancer.get_task(id)
        if task:
            task.ended.wait()
            return

        raise RpcException(errno.ENOENT, 'No such task')

    def abort(self, id):
        self.__balancer.abort(id)

    def list_resources(self):
        result = []
        for res in self.__dispatcher.resource_graph.nodes:
            result.append({
                'name': res.name,
                'busy': res.busy,
            })

        return result

    def list_executors(self):
        result = []
        for exe in self.__dispatcher.balancer.executors:
            result.append({
                'index': exe.index,
                'state': exe.state,
                'pid': exe.pid
            })

        return result

    @private
    def register_task_hook(self, hook, task, condition=None):
        self.__dispatcher.register_task_hook(hook, task, condition)

    @private
    def unregister_task_hook(self, hook, task):
        self.__dispatcher.unregister_task_hook(hook, task)

    @private
    def task_setenv(self, tid, key, value):
        task = self.__balancer.get_task(tid)
        if not task:
            raise RpcException(errno.ENOENT, 'Task {0} not found'.format(tid))

        if task.ended.is_set():
            raise RpcException(errno.ENOENT, 'Can set environment only for running tasks')

        task.set_env(key, value)

    @query('Task')
    @generator
    def query(self, filter=None, params=None):
        def extend(t):
            task = self.__balancer.get_task(t['id'])
            if task and task.progress:
                t['progress'] = task.progress.__getstate__()
                return t

            t['progress'] = {
                'percentage': 100 if t['state'] == 'FINISHED' else 0,
                'message': t['state'].lower().capitalize(),
                'extra': None
            }

            return t

        return self.__datastore.query_stream('tasks', *(filter or []), callback=extend, **(params or {}))

    @private
    @pass_sender
    def checkin(self, key, sender):
        executor = self.__balancer.get_executor_by_key(key)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        return executor.checkin(sender)

    @private
    @pass_sender
    def put_progress(self, progress, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        executor.put_progress(progress)

    @private
    @pass_sender
    def put_status(self, status, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        executor.put_status(status)

    @private
    @pass_sender
    def put_warning(self, warning, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        executor.put_warning(warning)

    @private
    @pass_sender
    def register_resource(self, resource, parents, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        self.__dispatcher.register_resource(Resource(resource), parents)

    @private
    @pass_sender
    def unregister_resource(self, resource, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        self.__dispatcher.unregister_resource(resource)

    @private
    @pass_sender
    def run_hook(self, hook, args, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        return self.__dispatcher.run_hook(hook, args)

    @private
    @pass_sender
    def verify_subtask(self, name, args, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        return self.__dispatcher.verify_subtask(executor.task, name, args)

    @private
    @pass_sender
    def run_subtask(self, name, args, env, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        ret = self.__balancer.run_subtask(executor.task, name, args, env)
        return ret.id

    @private
    @pass_sender
    def join_subtasks(self, subtask_ids, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        subtasks = list(map(self.__balancer.get_task, subtask_ids))
        self.__balancer.join_subtasks(*subtasks)

        for i in subtasks:
            if i.state != TaskState.FINISHED:
                raise RpcException(i.error['code'], i.error['message'])

        return [t.result for t in subtasks]

    @private
    @pass_sender
    def abort_subtask(self, id, sender):
        executor = self.__balancer.get_executor_by_sender(sender)
        if not executor:
            raise RpcException(errno.EPERM, 'Not authorized')

        self.__balancer.abort(id)

    @private
    def update_executor_environment(self, env):
        self.__balancer.update_executor_environment(env)


class LockService(RpcService):
    def initialize(self, context):
        self.locks = {}
        self.mutex = Semaphore()

    def init(self, lock):
        with self.mutex:
            if lock not in self.locks:
                self.locks[lock] = Semaphore()

    def acquire(self, lock, timo=None):
        with self.mutex:
            if lock not in self.locks:
                self.locks[lock] = Semaphore()

        return self.locks[lock].acquire(True, timo)

    def release(self, lock):
        with self.mutex:
            if lock not in self.locks:
                self.locks[lock] = Semaphore()
                return

        self.locks[lock].release()

    def is_locked(self, lock):
        with self.mutex:
            if lock not in self.locks:
                self.locks[lock] = Semaphore()
                return False

        return self.locks[lock].locked()

    def get_locks(self):
        return list(self.locks.keys())


class ShellService(RpcService):
    def initialize(self, context):
        self.dispatcher = context.dispatcher

    def get_shells(self):
        return self.dispatcher.configstore.get('system.shells')

    @pass_sender
    def execute(self, command, sender, input=None):
        proc = subprocess.Popen(
            ['/usr/bin/su', '-m', sender.user.name, '-c', command],
            stderr=subprocess.STDOUT,
            stdout=subprocess.PIPE,
            stdin=(subprocess.PIPE if input else None))

        out, _ = proc.communicate(input)
        proc.wait()
        return [proc.returncode, out]

    @pass_sender
    def spawn(self, shell, width, height, sender):
        return self.dispatcher.token_store.issue_token(
            ShellToken(user=sender.user, lifetime=60, shell=shell, width=width, height=height)
        )

    def resize(self, token, width, height):
        conn = self.dispatcher.token_store.lookup_token(token)
        if not conn:
            raise RpcException(errno.ENOENT, 'Connection not found')

        if not isinstance(conn, ShellToken):
            raise RpcException(errno.EINVAL, 'Wrong ticket type provided')

        if conn.resize:
            conn.resize(width, height)
