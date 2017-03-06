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
import argparse
import re
import datastore
import time
import json
import imp
import threading
from bsd import setproctitle
from datetime import timedelta, datetime
from datastore.config import ConfigStore
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.rpc import RpcService, RpcException
from freenas.utils import configure_logging
from freenas.utils.debug import DebugService
from freenas.serviced import checkin


DEFAULT_CONFIGFILE = '/usr/local/etc/middleware.conf'
REMINDER_SECONDS = 3600
REMINDER_SCHEDULE = {
    'CRITICAL': 1,
    'WARNING': 12,
    'INFO': None
}

operators_table = {
    '=': lambda x, y: x == y,
    '==': lambda x, y: x == y,
    '!=': lambda x, y: x != y,
    '>': lambda x, y: x > y,
    '<': lambda x, y: x < y,
    '>=': lambda x, y: x >= y,
    '<=': lambda x, y: x <= y,
    '~': lambda x, y: re.search(str(y), str(x)),
}


class AlertEmitter(object):
    def __init__(self, context):
        self.context = context

    def emit_first(self, alert, options):
        raise NotImplementedError()

    def emit_again(self, alert, options):
        raise NotImplementedError()

    def cancel(self, alert, options):
        raise NotImplementedError()


class ManagementService(RpcService):
    def __init__(self, ctx):
        self.context = ctx

    def rescan_plugins(self):
        self.context.scan_plugins()

    def die(self):
        pass


class AlertService(RpcService):
    def __init__(self, context):
        self.context = context

    def emit(self, id):
        alert = self.context.datastore.get_by_id('alerts', id)
        self.context.emit_alert(alert)

    def cancel(self, id):
        pass


class Main(object):
    def __init__(self):
        self.logger = logging.getLogger('alertd')
        self.config = None
        self.datastore = None
        self.configstore = None
        self.client = None
        self.plugin_dirs = []
        self.emitters = {}

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

    def init_reminder(self):
        t = threading.Thread(target=self.reminder_thread)
        t.daemon = True
        t.start()

    def parse_config(self, filename):
        try:
            f = open(filename, 'r')
            self.config = json.load(f)
            f.close()
        except IOError as err:
            self.logger.error('Cannot read config file: %s', err.message)
            sys.exit(1)
        except ValueError:
            self.logger.error('Config file has unreadable format (not valid JSON)')
            sys.exit(1)

        self.plugin_dirs = self.config['alertd']['plugin-dirs']

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('alertd')
                self.client.enable_server()
                self.client.register_service('alertd.management', ManagementService(self))
                self.client.register_service('alertd.alert', AlertService(self))
                self.client.register_service('alertd.debug', DebugService())
                self.client.resume_service('alertd.management')
                self.client.resume_service('alertd.alert')
                self.client.resume_service('alertd.debug')
                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

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
                plugin = imp.load_source(name, os.path.join(dir, f))
                plugin._init(self)
            except:
                self.logger.error('Cannot initialize plugin {0}'.format(f), exc_info=True)

    def emit_alert(self, alert):
        if 'clazz' not in alert or 'id' not in alert:
            self.logger.warning('Ignoring invalid alert <id:{0}>'.format(alert.get('id')))
            return

        self.logger.debug('Emitting alert <id:{0}> (class {1})'.format(alert['id'], alert['clazz']))
        for i in self.datastore.query('alert.filters', ('or', [
            ('clazz', '=', None),
            ('clazz', '=', alert['clazz'])
        ])):
            for pr in i.get('predicates', []):
                if pr['operator'] not in operators_table:
                    continue

                try:
                    if not operators_table[pr['operator']](alert.properties.get(pr['property']), pr['value']):
                        break
                except:
                    continue
            else:
                try:
                    emitter = self.emitters.get(i['emitter'])
                    if not emitter:
                        self.logger.warning('Invalid emitter {0} for alert filter {1}'.format(i['emitter'], i['id']))
                        continue

                    self.logger.debug('Alert <id:{0}> matched filter {1}'.format(alert['id'], i['id']))
                    if alert['send_count'] > 0:
                        if not alert['one_shot']:
                            emitter.emit_again(alert, i['parameters'])
                    else:
                        emitter.emit_first(alert, i['parameters'])
                except BaseException as err:
                    # Failed to emit alert using alert emitter
                    # XXX: generate another alert about that
                    self.logger.error('Cannot emit alert <id:{0}> using {1}: {2}'.format(
                        alert['id'],
                        i['emitter'],
                        str(err))
                    )

        alert['send_count'] += 1
        alert['last_emitted_at'] = datetime.utcnow()
        self.datastore.update('alerts', alert['id'], alert)

    def cancel_alert(self, alert):
        self.logger.debug('Cancelling alert <id:{0}> (class {1})'.format(alert['id'], alert['clazz']))

        alert.update({
            'active': False,
            'cancelled': datetime.utcnow()
        })

        self.datastore.update('alerts', alert['id'], alert)

    def register_emitter(self, name, cls):
        self.emitters[name] = cls(self)
        self.logger.info('Registered emitter {0} (class {1})'.format(name, cls))

    def reminder_thread(self):
        while True:
            time.sleep(REMINDER_SECONDS)
            for i in self.datastore.query('alerts'):
                if not i['active'] or i['dismissed']:
                    continue

                last_emission = i.get('last_emitted_at') or i['created_at']
                interval = REMINDER_SCHEDULE[i['severity']]

                if not interval:
                    continue

                if last_emission + timedelta(seconds=interval) <= datetime.utcnow():
                    self.emit_alert(i)

    def checkin(self):
        checkin()

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Middleware config file')
        args = parser.parse_args()
        configure_logging('alertd', 'DEBUG')

        setproctitle('alertd')
        self.config = args.c
        self.parse_config(self.config)
        self.init_datastore()
        self.init_dispatcher()
        self.scan_plugins()
        self.init_reminder()
        self.checkin()
        self.client.wait_forever()


if __name__ == '__main__':
    m = Main()
    m.main()

