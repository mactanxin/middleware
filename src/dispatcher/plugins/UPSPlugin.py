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

import io
import csv
import errno
import logging
import os
import re
import socket
import time

from datastore.config import ConfigNode
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, private, returns
from lib.system import system, SubprocessException
from task import Task, Provider, TaskException, TaskDescription

logger = logging.getLogger('UPSPlugin')


@description('Provides info about UPS service configuration')
class UPSProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('service-ups'))
    def get_config(self):
        return ConfigNode('service.ups', self.configstore).__getstate__()

    @accepts()
    @returns(h.array(h.array(str)))
    def drivers(self):
        driver_list = '/usr/local/libexec/nut/driver.list'
        if not os.path.exists(driver_list):
            return []
        drivers = []
        with open(driver_list, 'rb') as f:
            d = f.read()
        r = io.StringIO()
        for line in re.sub(r'[ \t]+', ' ', d.decode('utf-8'), flags=re.M).split('\n'):
            r.write(line.strip() + '\n')
        r.seek(0)
        reader = csv.reader(r, delimiter=' ', quotechar='"')
        for row in reader:
            if len(row) == 0 or row[0].startswith('#'):
                continue
            if row[-2] == '#':
                last = -3
            else:
                last = -1
            if row[last].find(' (experimental)') != -1:
                row[last] = row[last].replace(' (experimental)', '').strip()
            drivers.append({'driver_name': row[last], 'description': '{0} ({1})'.format(
                ' '.join(row[0:last]), row[last]
            )})
        return drivers

    @accepts()
    @returns(h.array(h.array(str)))
    def get_usb_devices(self):
        usb_devices_list = []
        try:
            usbconfig_output = system('usbconfig')[0]
            if not usbconfig_output.startswith('No device match'):
                for device in usbconfig_output.rstrip().split('\n'):
                    device_path = os.path.join('/dev', device.split()[0][:-1])
                    device_description = re.findall(r'<.*?>', device)[0].strip('><')
                    usb_devices_list.append({'device': device_path, 'description': device_description})

        except SubprocessException as e:
            raise TaskException(errno.EBUSY, e.err)

        return usb_devices_list

    @private
    def service_start(self):
        ups = self.get_config()
        if ups['mode'] == 'MASTER':
            rc_scripts = ['nut']
        else:
            rc_scripts = []
        rc_scripts.extend(['nut_upslog', 'nut_upsmon'])

        try:
            for i in rc_scripts:
                system("/usr/sbin/service", i, 'onestart')
        except SubprocessException as e:
            raise TaskException(errno.EBUSY, e.err)

    @private
    def service_status(self):
        ups = self.get_config()
        if ups['mode'] == 'MASTER':
            rc_scripts = ['nut']
        else:
            rc_scripts = []
        rc_scripts.extend(['nut_upslog', 'nut_upsmon'])

        try:
            for i in rc_scripts:
                system("/usr/sbin/service", i, 'onestatus')
        except SubprocessException as e:
            raise TaskException(errno.EBUSY, e.err)

    @private
    def service_stop(self):
        ups = self.get_config()
        rc_scripts = ['nut_upslog', 'nut_upsmon']
        if ups['mode'] == 'MASTER':
            rc_scripts.append('nut')

        try:
            for i in rc_scripts:
                system("/usr/sbin/service", i, 'onestop')
        except SubprocessException as e:
            raise TaskException(errno.EBUSY, e.err)

    @private
    def service_restart(self):
        ups = self.get_config()
        # Stop monitor so it wont trigger signals when nut restarts
        verbs = [
            ('nut_upsmon', 'stop'),
            ('nut_upslog', 'restart'),
        ]
        if ups['mode'] == 'MASTER':
            verbs.append(('nut', 'restart'))
        verbs.append(('nut_upsmon', 'start'))

        try:
            for svc, verb in verbs:
                system("/usr/sbin/service", svc, 'one' + verb)
        except SubprocessException as e:
            raise TaskException(errno.EBUSY, e.err)


@private
@description('Configure UPS service')
@accepts(h.ref('service-ups'))
class UPSConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring UPS service'

    def describe(self, ups):
        return TaskDescription('Configuring UPS service')

    def verify(self, ups):
        return ['system']

    def run(self, ups):
        node = ConfigNode('service.ups', self.configstore).__getstate__()
        node.update(ups)

        if node['mode'] == 'MASTER' and (not node['driver_port'] or not node['driver']):
            raise TaskException(errno.EINVAL, 'Please provide a valid port and driver for monitored UPS device')

        if node['mode'] == 'SLAVE' and not node['remote_host']:
            raise TaskException(errno.EINVAL, 'This field is required')

        if not re.search(r'^[a-z0-9\.\-_]+$', node['identifier'], re.I):
            raise TaskException(errno.EINVAL, 'Use alphanumeric characters, ".", "-" and "_"')

        for i in ('monitor_user', 'monitor_password'):
            if re.search(r'[ #]', node[i], re.I):
                raise TaskException(errno.EINVAL, 'Spaces or number signs are not allowed')

        try:
            node = ConfigNode('service.ups', self.configstore)
            node.update(ups)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'services')
            self.dispatcher.call_sync('etcd.generation.generate_group', 'ups')
            self.dispatcher.dispatch_event('service.ups.changed', {
                'operation': 'updated',
                'ids': None,
            })
        except RpcException as e:
            raise TaskException(
                errno.ENXIO, 'Cannot reconfigure UPS: {0}'.format(str(e))
            )

        return 'RESTART'


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):

    def ups_signal(kwargs):
        ups = dispatcher.call_sync('service.ups.get_config')

        name = kwargs.get('name')
        notifytype = kwargs.get('type')

        if name == 'ONBATT':
            if ups['shutdown_mode'] == 'BATT':
                logger.warn('Issuing shutdown from UPS signal')
                system('/usr/local/sbin/upsmon', '-c', 'fsd')

        elif name in ('EMAIL', 'COMMBAD', 'COMMOK'):
            if ups['email_notify'] and ups['email_recipients']:
                subject = ups['email_subject'].replace('%d', time.asctime()).replace('%h', socket.gethostname())
                dispatcher.call_sync('mail.send', {
                    'to': ups['email_recipients'],
                    'subject': subject,
                    'message': 'UPS Status: {0}\n'.format(
                        notifytype,
                    ),
                })
            else:
                logger.debug('Email not configured for UPS')
        else:
            logger.info('Unhandled UPS Signal: %s', name)

    # Register schemas
    plugin.register_schema_definition('service-ups', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['service-ups']},
            'enable': {'type': 'boolean'},
            'mode': {'$ref': 'service-ups-mode'},
            'identifier': {'type': 'string'},
            'remote_host': {'type': ['string', 'null']},
            'remote_port': {'type': 'integer'},
            'driver': {'type': 'string'},
            'driver_port': {'type': ['string', 'null']},
            'description': {'type': ['string', 'null']},
            'shutdown_mode': {'$ref': 'service-ups-shutdownmode'},
            'shutdown_timer': {'type': 'integer'},
            'monitor_user': {'type': 'string'},
            'monitor_password': {'type': 'string'},
            'allow_remote_connections': {'type': 'boolean'},
            'auxiliary_users': {'type': ['string', 'null']},
            'email_notify': {'type': 'boolean'},
            'email_recipients': {'type': 'array', 'items': {'$ref': 'email'}},
            'email_subject': {'type': 'string'},
            'powerdown': {'type': 'boolean'},
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('service-ups-mode', {
        'type': 'string',
        'enum': ['MASTER', 'SLAVE']
    })
    plugin.register_schema_definition('service-ups-shutdownmode', {
        'type': 'string',
        'enum': ['LOWBATT', 'BATT']
    })


    # Register providers
    plugin.register_provider("service.ups", UPSProvider)

    # Register tasks
    plugin.register_task_handler("service.ups.update", UPSConfigureTask)

    # Register events
    plugin.register_event_type('service.ups.signal')
    plugin.register_event_handler('service.ups.signal', ups_signal)
