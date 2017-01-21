#
# Copyright 2017 iXsystems, Inc.
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

import uuid
import os
import sys
import re
import socket
import threading
import collections
import signal
import logging
import itertools
import time
import datastore
from datetime import datetime
from bsd import SyslogPriority, SyslogFacility
from freenas.dispatcher.server import Server
from freenas.dispatcher.rpc import RpcContext, RpcService, RpcException, generator
from freenas.serviced import checkin
from freenas.utils import query as q


FLUSH_INTERVAL = 180
SYSLOG_PATTERN = re.compile(r'<(?P<priority>\d+)>(?P<timestamp>\w+ \d+ \d+:\d+:\d+) (?P<process>[\w\[\]]+): (?P<message>.*)')
KLOG_PATTERN = re.compile(r'<(?P<priority>\d+)>(?P<message>.*)')
PROC_PATTERN = re.compile(r'(?P<name>\w+)\[(?P<pid>\d+)\]')
DEFAULT_SOCKET_ADDRESS = 'unix:///var/run/logd.sock'
KLOG_PATH = '/dev/klog'
SYSLOG_SOCKETS = {
    '/var/run/log': 0o666,
    '/var/run/logpriv': 0o600
}


def parse_priority(prio):
    return prio & 0x7, prio << 3


class LoggingService(RpcService):
    def __init__(self, context):
        self.context = context

    def get_boot_id(self):
        return self.context.boot_id

    def set_flush(self, enable):
        with self.context.cv:
            self.context.flush = bool(enable)
            self.context.cv.notify_all()

    def log(self, priority, progname, message, args):
        pass

    @generator
    def query(self, filter=None, params=None):
        return itertools.chain(
            q.query(self.context.store, *(filter or []), **(params or {}))
        )


class KernelLogReader(object):
    def __init__(self, context):
        self.context = context

    def process(self):
        while True:
            with open(KLOG_PATH, 'rb') as fp:
                for line in fp:
                    # Skip lines with 'ESC' character inside
                    if '\033' in line:
                        continue

                    m = KLOG_PATTERN.match(line)
                    if not m:
                        continue

                    m = m.groupdict()
                    self.context.push({
                        'priority': m['priority'],
                        'message': m['message'],
                        'process': 'kernel',
                        'timestamp': datetime.utcnow()
                    })

            logging.warning('Lost connection to {0}, retrying in 1 second'.format(KLOG_PATH))
            time.sleep(1)


class SyslogServer(object):
    def __init__(self, path, perms, context):
        super(SyslogServer, self).__init__()
        self.context = context
        self.path = path
        self.perms = perms
        self.thread = None
        self.sock = None

        if os.path.exists(path):
            os.unlink(path)

    def start(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        self.sock.bind(self.path)
        os.chmod(self.path, self.perms)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def parse_message(self, msg):
        m = SYSLOG_PATTERN.match(msg.decode('utf-8'))
        if not m:
            return

        m = m.groupdict()
        m['priority'] = int(m['priority'])
        m['timestamp'] = datetime.strptime(m['timestamp'], '%b %d %H:%M:%S')

        p = PROC_PATTERN.match(m['process'])
        if not p:
            return m

        p = p.groupdict()
        m['process'] = p['name']
        m['pid'] = int(p['pid'])
        return m

    def serve(self):
        while True:
            msg, ancdata, flags, address = self.sock.recvmsg(1024)
            if not msg:
                break

            with self.context.lock:
                item = self.parse_message(msg)
                self.context.push(item)


class SyslogForwarder(object):
    def __init__(self, host, port, context):
        self.host = host
        self.port = port
        self.context = context


class Context(object):
    def __init__(self):
        self.store = collections.deque()
        self.lock = threading.Lock()
        self.rpc_server = Server(self)
        self.boot_id = str(uuid.uuid4())
        self.server = None
        self.servers = []
        self.flush = False
        self.datastore = None
        self.rpc = RpcContext()
        self.rpc.register_service_instance('logd.logging', LoggingService(self))
        self.cv = threading.Condition()

    def init_datastore(self):
        try:
            self.datastore = datastore.get_datastore()
        except datastore.DatastoreException as err:
            logging.error('Cannot initialize datastore: %s', str(err))
            sys.exit(1)

    def init_rpc_server(self):
        self.server = Server(self)
        self.server.rpc = self.rpc
        self.server.streaming = True
        self.server.start(DEFAULT_SOCKET_ADDRESS, transport_options={'permissions': 0o666})
        self.server.serve_forever()

    def init_syslog_server(self):
        for path, perm in SYSLOG_SOCKETS.items():
            server = SyslogServer(path, perm, self)
            server.start()
            self.servers.append(server)

        signal.pause()

    def push(self, item):
        with self.lock:
            priority, facility = parse_priority(int(item['priority']))
            item.udpate({
                'id': uuid.uuid4(),
                'boot_id': self.boot_id,
                'priority': priority,
                'facility': facility
            })
            self.store.append(item)

    def flush(self):
        while True:
            # Flush immediately after getting wakeup or when timeout expires
            self.cv.wait(FLUSH_INTERVAL)

            if not self.flush:
                continue

            logging.debug('Attempting to flush logs')
            self.init_datastore()
            with self.lock:
                for i in self.store:
                    self.datastore.insert('syslog', i)

                count = len(self.store)
                self.store.clear()

            logging.debug('Flushed {0} log items'.format(count))

    def main(self):
        self.init_syslog_server()
        self.init_rpc_server()
        checkin()


if __name__ == '__main__':
    c = Context()
    c.main()
