#!/usr/local/bin/python3
#
# Copyright 2014-2016 iXsystems, Inc.
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
import logging
import socket
import argparse
import datastore
import time
import json
from bsd import setproctitle
from datastore.config import ConfigStore
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.rpc import RpcService, RpcException, generator
from freenas.utils import configure_logging, load_module_from_file
from freenas.utils.debug import DebugService
from freenas.serviced import checkin


DEFAULT_CONFIGFILE = '/usr/local/etc/middleware.conf'


class ManagementService(RpcService):
    def __init__(self, ctx):
        self.context = ctx

    def die(self):
        pass


class DiscoveryService(RpcService):
    def __init__(self, context):
        self.context = context

    @generator
    def find(self, regtype):
        for name, plugin in self.context.plugins.items():
            for svc in plugin.find(regtype):
                svc['source'] = name
                yield svc


class Main(object):
    def __init__(self):
        self.logger = logging.getLogger('neighbord')
        self.config = None
        self.datastore = None
        self.configstore = None
        self.client = None
        self.config = None
        self.logger = logging.getLogger()
        self.plugin_dirs = []
        self.plugins = {}

    def parse_config(self, filename):
        try:
            with open(filename, 'r') as f:
                self.config = json.load(f)
        except IOError as err:
            self.logger.error('Cannot read config file: %s', err.message)
            sys.exit(1)
        except ValueError:
            self.logger.error('Config file has unreadable format (not valid JSON)')
            sys.exit(1)

        self.plugin_dirs = self.config['neighbord']['plugin-dirs']

    def init_datastore(self):
        try:
            self.datastore = datastore.get_datastore()
        except datastore.DatastoreException as err:
            self.logger.error('Cannot initialize datastore: %s', str(err))
            sys.exit(1)

        self.configstore = ConfigStore(self.datastore)

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect()

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def scan_plugins(self):
        for i in self.plugin_dirs:
            self.scan_plugin_dir(i)

    def scan_plugin_dir(self, dir):
        self.logger.debug('Scanning plugin directory %s', dir)
        for f in os.listdir(dir):
            name, ext = os.path.splitext(os.path.basename(f))
            if ext != '.py':
                continue

            try:
                plugin = load_module_from_file(name, os.path.join(dir, f))
                plugin._init(self)
            except:
                self.logger.error('Cannot initialize plugin {0}'.format(f), exc_info=True)

    def register_plugin(self, name, cls):
        self.plugins[name] = cls(self)
        self.logger.info('Registered plugin {0} (class {1})'.format(name, cls))

    def register_service(self, name, regtype, port, properties=None):
        for plugin in self.plugins.values():
            plugin.register(regtype, name, port, properties)

    def register(self):
        try:
            hostname = socket.gethostname()
            general = self.client.call_sync('system.general.get_config')
            properties = {
                'version': self.client.call_sync('system.info.version'),
                'description': general['description'],
                'tags': ','.join(general['tags'])
            }

            self.register_service(hostname, 'freenas', 80, properties)
            self.register_service(hostname, 'http', 80)
            self.register_service(hostname, 'ssh', 22)
            self.register_service(hostname, 'sftp-ssh', 22)
        except BaseException as err:
            self.logger.error('Failed to register services: {0}'.format(str(err)))

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('neighbord')
                self.client.enable_server()
                self.client.register_service('neighbord.management', ManagementService(self))
                self.client.register_service('neighbord.discovery', DiscoveryService(self))
                self.client.register_service('neighbord.debug', DebugService())
                self.client.resume_service('neighbord.management')
                self.client.resume_service('neighbord.discovery')
                self.client.resume_service('neighbord.debug')
                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def checkin(self):
        checkin()

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Middleware config file')
        args = parser.parse_args()
        self.config = args.c
        configure_logging('neighbord', 'DEBUG')

        setproctitle('neighbord')
        self.parse_config(self.config)
        self.init_datastore()
        self.init_dispatcher()
        self.scan_plugins()
        self.register()
        self.checkin()
        self.client.wait_forever()


if __name__ == '__main__':
    m = Main()
    m.main()

