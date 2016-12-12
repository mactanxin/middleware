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
import sys
import io
import pty
import errno
import signal
import enum
import uuid
import json
import glob
import setproctitle
import tempfile
import time
import subprocess
import socket
import threading
import logging
import argparse
import select
import socket
import tarfile
import bsd
import mmap
import msock.channel
import msock.client
from datetime import datetime
from threading import Condition
from freenas.dispatcher.rpc import RpcContext, RpcService, RpcException, generator
from freenas.dispatcher.fd import MSockChannelSerializer
from freenas.dispatcher.bridge import Bridge
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.server import Server
from freenas.utils.permissions import get_type
from freenas.serviced import checkin


DS2 = '/usr/local/bin/ds2'
CORES_DIR = '/var/db/system/cores'
DEFAULT_CONFIGFILE = '/usr/local/etc/debugd.conf'
DEFAULT_SOCKET_ADDRESS = 'unix:///var/run/debugd.sock'
SUPPORT_PROXY_ADDRESS = 'tcp://kielbasa.ixsystems.com:8080'


def get_version():
    with open('/etc/version', 'r') as f:
        version, _ = f.read().split()
        return version


class ConnectionState(enum.Enum):
    OFFLINE = 'offline'
    CONNECTING = 'connecting'
    CONNECTED = 'connected'
    LOST = 'lost'


class DebugService(RpcService):
    def __init__(self, context):
        self.context = context

    def shell(self, args, fd):
        self.context.run_job(ShellConnection(args, fd))

    def download(self, path, fd):
        job = FileConnection(path, False, fd)
        size = job.filesize
        self.context.run_job(job)
        return size

    def upload(self, path, fd):
        job = FileConnection(path, True, fd)
        self.context.run_job(job)

    def tail(self, path, scrollback_size, fd):
        self.context.run_job(TailConnection(path, scrollback_size, fd))

    def dashboard(self, fd):
        self.context.run_job(DashboardConnection(fd))

    @generator
    def listdir(self, directory):
        for i in sorted(os.listdir(directory)):
            path = os.path.join(directory, i)
            stat = os.lstat(path)
            yield {
                'type': get_type(stat),
                'size': stat.st_size,
                'created_at': datetime.utcfromtimestamp(stat.st_ctime),
                'modified_at': datetime.utcfromtimestamp(stat.st_mtime),
                'name': i,
                'path': path
            }

    @generator
    def get_process_list(self):
        procs = bsd.getprocs(bsd.ProcessLookupPredicate.PROC)
        for i in procs:
            try:
                argv = list(i.argv)
                yield {
                    'pid': i.pid,
                    'title': argv[0],
                    'command': i.command,
                    'argv': argv,
                    'env': list(i.env)
                }
            except:
                continue

    @generator
    def get_core_files(self):
        for i in os.listdir(CORES_DIR):
            try:
                path = os.path.join(CORES_DIR, i)
                proc = bsd.opencore(path)
                stat = os.stat(path)
                yield {
                    'pid': proc.pid,
                    'command': proc.command,
                    'argv': list(proc.argv),
                    'created_at': datetime.utcfromtimestamp(stat.st_ctime),
                    'size': stat.st_size
                }
            except OSError:
                continue

    @generator
    def get_log_files(self):
        for pattern in self.context.config.get('log_paths', []):
            for i in glob.glob(pattern):
                yield i

    def trace_process(self, pid, fd):
        self.context.run_job(ShellConnection(['/usr/bin/truss', '-p', str(pid)], fd))

    def debug_process(self, pid, gdb, fd):
        try:
            proc = bsd.kinfo_getproc(pid)
        except LookupError:
            raise RpcException(errno.ENOENT, 'PID {0} not found'.format(pid))

        self.context.run_job(DebugServerConnection(pid, gdb, fd))
        return proc.path

    def proxy_dispatcher_rpc(self, fd):
        br = Bridge()
        br.start('unix:', 'fd://{0}'.format(fd.fd))


class ControlService(RpcService):
    def __init__(self, context):
        self.context = context

    def connect(self, discard=False):
        self.context.connect(discard)

    def disconnect(self):
        self.context.disconnect()

    def status(self):
        return {
            'state': self.context.state.name,
            'server': DEFAULT_SOCKET_ADDRESS,
            'connection_id': str(self.context.connection_id),
            'connected_at': self.context.connected_at,
            'jobs': [j.__getstate__() for j in self.context.jobs]
        }

    def upload(self, filename, description, fd):
        pass


class Job(object):
    def __init__(self):
        self.context = None
        self.thread = None
        self.created_at = datetime.now()
        self.ended_at = None

    def describe(self):
        raise NotImplementedError()

    def close(self):
        if self.context:
            self.context.jobs.remove(self)

    def start(self):
        if hasattr(self, 'worker'):
            self.thread = threading.Thread(target=self.worker, daemon=True, name='worker thread')
            self.thread.start()

    def __getstate__(self):
        return {
            'created_at': self.created_at,
            'ended_at': self.ended_at,
            'description': self.describe()
        }


class ShellConnection(Job):
    def __init__(self, args, fd):
        super(ShellConnection, self).__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info('Attempting to start shell session of {0}'.format(args))
        self.args = args
        self.fd = fd.fd
        self.channel = None

        try:
            self.pid, self.master = pty.fork()

            if self.pid == 0:
                os.putenv('TERM', 'xterm')
                os.putenv('PATH', '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin')
                os.execv(args[0], args)

            self.logger.info('Spawned {0} as pid {1}'.format(args, self.pid))
        except OSError as err:
            self.logger.error('Cannot start shell connection: {0}'.format(str(err)))
            self.close()

    def describe(self):
        return "Shell: {0}".format(' '.join(self.args))

    def reader(self):
        while True:
            data = self.channel.recv(1024)
            if data == b'':
                os.close(self.master)
                return

            os.write(self.master, data)

    def worker(self):
        self.channel = self.context.msock.channels[self.fd]
        threading.Thread(target=self.reader, daemon=True).start()
        while True:
            data = os.read(self.master, 1024)
            if data == b'':
                self.logger.debug('Closing shell session')
                self.close()
                return

            self.channel.write(data)


class FileConnection(Job):
    def __init__(self, path, upload, fd):
        super(FileConnection, self).__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.upload = upload
        self.path = path
        self.fd = fd.fd
        self.file = open(path, 'wb' if upload else 'rb')
        self.logger.info('Initiating {0} of file {1}'.format('upload' if self.upload else 'download', self.path))

    @property
    def filesize(self):
        stat = os.stat(self.path)
        return stat.st_size

    def describe(self):
        return "File {0}: {1}".format('upload' if self.upload else 'download', self.path)

    def worker(self):
        with io.open(self.fd, 'rb' if self.upload else 'wb') as fd:
            while True:
                data = fd.read1(1024) if self.upload else self.file.read(1024)
                if data == b'':
                    fd.close()
                    self.file.close()
                    self.close()
                    return

                if self.upload:
                    self.file.write(data)
                else:
                    fd.write(data)


class TailConnection(Job):
    def __init__(self, path, backlog, fd):
        super(TailConnection, self).__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.path = path
        self.fd = fd.fd
        self.backlog = backlog

    def describe(self):
        return "File watch: {0}".format(self.path)

    def tail(self, f, n):
        fm = mmap.mmap(f.fileno(), 0, mmap.MAP_SHARED, mmap.PROT_READ)
        try:
            for i in range(fm.size() - 1, -1, -1):
                if fm[i] == ord(b'\n'):
                    n -= 1
                    if n == -1:
                        break
            return fm[i + 1 if i else 0:]
        finally:
            fm.close()

    def worker(self):
        self.logger.debug('Opened tail stream on file {0} ({1} lines)'.format(self.path, self.backlog))
        with io.open(self.fd, 'wb') as fd:
            with open(self.path, 'rb') as f:
                kq = select.kqueue()
                try:
                    ev = [
                        select.kevent(fd.fileno(), filter=select.KQ_FILTER_READ, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE),
                        select.kevent(f.fileno(), filter=select.KQ_FILTER_READ, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE)
                    ]

                    fd.write(self.tail(f, self.backlog))
                    fd.flush()

                    kq.control(ev, 0)
                    f.seek(0, os.SEEK_END)

                    while True:
                        event, = kq.control(None, 1)
                        self.logger.debug('kqueue event {0}'.format(event))
                        if event.ident == fd.fileno():
                            if event.flags & select.KQ_EV_EOF or event.flags & select.KQ_EV_ERROR:
                                break

                        if event.ident == f.fileno():
                            fd.write(f.read())
                            fd.flush()
                finally:
                    kq.close()


class DashboardConnection(Job):
    def __init__(self, fd):
        super(DashboardConnection, self).__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.fd = fd.fd

    def describe(self):
        return "Dashboard snapshot upload"

    def worker(self):
        fd = os.fdopen(self.fd, 'wb')
        tar = tarfile.open(fileobj=fd, mode='w|')

        self.logger.debug('Opened dashboard stream')

        try:
            for name, cmd in self.context.config.get('dashboard', {}).items():
                try:
                    out = subprocess.check_output(cmd)
                    buf = io.BytesIO(out)
                    info = tarfile.TarInfo(name)
                    info.size = len(out)
                    tar.addfile(info, buf)
                    self.logger.debug('Added output of {0}'.format(cmd))
                except subprocess.CalledProcessError as err:
                    self.logger.error('Command failed: {0}'.format(str(err)))
                    continue

            tar.close()
            fd.close()
            self.logger.debug('Stream closed')
        except BaseException as err:
            self.logger.exception('sad')


class DebugServerConnection(Job):
    def __init__(self, pid, gdb, fd):
        super(DebugServerConnection, self).__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.pid = pid
        self.fd = fd.fd
        self.fifoname = '/tmp/ds2.{0}.fifo'.format(self.pid)
        self.args = [DS2, 'g', '-N', self.fifoname, '-a', str(pid)]
        if gdb:
            self.args.insert(2, '-g')

    def describe(self):
        return "Debug server connection (pid {0})".format(self.pid)

    def worker(self):
        self.logger.debug('Opening debug session for PID {0}'.format(self.pid))

        os.mkfifo(self.fifoname)
        proc = subprocess.Popen(self.args)

        with open(self.fifoname) as fifo:
            port = int(fifo.read()[:-1])

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        sock.connect(('localhost', port))
        with io.open(self.fd, 'r+b', buffering=0) as fd:
            with sock.makefile('rwb', buffering=0) as s:
                while True:
                    r, _, _ = select.select([fd, s], [], [])
                    for f in r:
                        data = f.read(1024)
                        if data == b'':
                            self.logger.debug('Closing debug session')
                            self.close()
                            break

                        if f == fd:
                            s.write(data)
                        else:
                            fd.write(data)
                    else:
                        continue

                    break

        sock.shutdown(socket.SHUT_RDWR)
        sock.close()
        proc.wait()
        os.unlink(self.fifoname)


class Context(object):
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.msock = msock.client.Client()
        self.msock.on_closed = self.on_msock_close
        self.rpc_fd = -1
        self.connection_id = None
        self.jobs = []
        self.state = ConnectionState.OFFLINE
        self.config = None
        self.keepalive = None
        self.connected_at = None
        self.cv = Condition()
        self.rpc = RpcContext()
        self.client = Client()
        self.server = Server()
        self.middleware_endpoint = None

    def start(self, configpath, sockpath):
        signal.signal(signal.SIGUSR2, lambda signo, frame: self.connect())
        self.read_config(configpath)
        self.server.rpc = RpcContext()
        self.server.rpc.register_service_instance('control', ControlService(self))
        self.server.start(sockpath)
        threading.Thread(target=self.server.serve_forever, name='server thread', daemon=True).start()

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect_dispatcher()

        self.middleware_endpoint = Client()
        self.middleware_endpoint.on_error(on_error)
        self.connect_dispatcher()

    def connect_dispatcher(self):
        while True:
            try:
                self.middleware_endpoint.connect('unix:')
                self.middleware_endpoint.login_service('debugd')
                self.middleware_endpoint.enable_server()
                self.middleware_endpoint.register_service('debugd.management', ControlService(self))
                self.middleware_endpoint.resume_service('debugd.management')
                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def read_config(self, path):
        try:
            with open(path) as f:
                self.config = json.load(f)
        except (IOError, OSError, ValueError) as err:
            self.logger.fatal('Cannot open config file: {0}'.format(str(err)))
            self.logger.fatal('Exiting.')
            sys.exit(1)

    def connect(self, discard=False):
        if discard:
            self.connection_id = None

        self.keepalive = threading.Thread(target=self.connect_keepalive, daemon=True)
        self.keepalive.start()

    def connect_keepalive(self):
        while True:
            try:
                if not self.connection_id:
                    self.connection_id = uuid.uuid4()

                self.msock.connect(SUPPORT_PROXY_ADDRESS)
                self.logger.info('Connecting to {0}'.format(SUPPORT_PROXY_ADDRESS))
                self.rpc_fd = self.msock.create_channel(0)
                time.sleep(1)  # FIXME
                self.client = Client()
                self.client.connect('fd://', fobj=self.rpc_fd)
                self.client.channel_serializer = MSockChannelSerializer(self.msock)
                self.client.standalone_server = True
                self.client.enable_server()
                self.client.register_service('debug', DebugService(self))
                self.client.call_sync('server.login', str(self.connection_id), socket.gethostname(), get_version(), 'none')
                self.set_state(ConnectionState.CONNECTED)
            except BaseException as err:
                self.logger.warning('Failed to initiate support connection: {0}'.format(err), exc_info=True)
                self.msock.disconnect()
            else:
                self.connected_at = datetime.now()
                with self.cv:
                    self.cv.wait_for(lambda: self.state in (ConnectionState.LOST, ConnectionState.OFFLINE))
                    if self.state == ConnectionState.OFFLINE:
                        return

            self.logger.warning('Support connection lost, retrying in 10 seconds')
            time.sleep(10)

    def disconnect(self):
        self.connected_at = None
        self.set_state(ConnectionState.OFFLINE)
        self.client.disconnect()
        self.msock.destroy_channel(0)
        self.msock.disconnect()
        self.jobs.clear()

    def on_msock_close(self):
        self.connected_at = None
        self.set_state(ConnectionState.LOST)

    def run_job(self, job):
        self.jobs.append(job)
        job.context = self
        job.start()

    def set_state(self, state):
        with self.cv:
            self.state = state
            self.cv.notify_all()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', metavar='SOCKET', default=DEFAULT_SOCKET_ADDRESS, help='Socket address to listen on')
    parser.add_argument('-c', metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Configuration file path')
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG)
    context = Context()
    context.start(args.c, args.s)
    context.init_dispatcher()
    setproctitle.setproctitle('debugd')

    if not os.path.isdir(CORES_DIR):
        os.mkdir(CORES_DIR)

    checkin()

    while True:
        time.sleep(60)


if __name__ == '__main__':
    main()
