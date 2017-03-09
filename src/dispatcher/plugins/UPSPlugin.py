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

from datastore.config import ConfigNode
from freenas.dispatcher import Password
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, description, accepts, private, returns
from lib.system import system, SubprocessException
from task import Task, Provider, TaskException, TaskDescription
from freenas.utils.password import unpassword


logger = logging.getLogger('UPSPlugin')

nut_signal_descriptions = {
    'ONLINE': 'UPS is back online',
    'ONBATT': 'UPS is on battery',
    'LOWBATT': 'UPS is on battery and has a low battery',
    'COMMOK': 'Communications established with the UPS',
    'COMMBAD': 'Communications lost to the UPS',
    'REPLBATT': 'The UPS battery is bad and needs to be replaced',
    'NOCOMM': 'A UPS is unavailable (can’t be contacted for monitoring)',
    'SHUTDOWN': 'The local system is going to be shut down',
    'FSD': 'The UPS is in the "forced shutdown" mode'
}


@description('Provides info about UPS service configuration')
class UPSProvider(Provider):
    @private
    @accepts()
    @returns(h.ref('ServiceUps'))
    def get_config(self):
        state = ConfigNode('service.ups', self.configstore).__getstate__()
        state['monitor_password'] = Password(state['monitor_password'])
        return state

    @accepts()
    @returns(h.array(h.array(str)))
    def drivers(self):
        driver_list = '/etc/local/nut/driver.list'
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
@description('Configure UPS service')
@accepts(h.ref('ServiceUps'))
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
        if 'monitor_password' in ups:
            ups['monitor_password'] = unpassword(ups['monitor_password'])

        node.update(ups)

        if node['mode'] == 'MASTER' and (not node['driver_port'] or not node['driver']):
            raise TaskException(errno.EINVAL, 'Please provide a valid port and driver for monitored UPS device')

        if node['mode'] == 'SLAVE' and not node['remote_host']:
            raise TaskException(errno.EINVAL, 'remote_host field is required in SLAVE mode')

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
        logger.info('UPS Signal: %s received', name)

        if name == 'ONBATT':
            if ups['propagate_alerts']:
                dispatcher.call_sync('alert.emit', {
                    'description': nut_signal_descriptions[name],
                    'title' :'UPS signal received',
                    'clazz': 'UpsSignal'
                })

            if ups['shutdown_mode'] == 'BATT':
                system('/usr/local/sbin/upsmon', '-c', 'fsd')

        elif ups['propagate_alerts']:
            dispatcher.call_sync('alert.emit', {
                'description': nut_signal_descriptions[name],
                'title': 'UPS signal received',
                'clazz': 'UpsSignal'
            })

    # Register schemas
    plugin.register_schema_definition('ServiceUps', {
        'type': 'object',
        'properties': {
            'type': {'enum': ['ServiceUps']},
            'enable': {'type': 'boolean'},
            'mode': {'$ref': 'ServiceUpsMode'},
            'identifier': {'type': 'string'},
            'remote_host': {'type': ['string', 'null']},
            'remote_port': {'type': 'integer'},
            'driver': {'type': ['string', 'null']},
            'driver_port': {'type': ['string', 'null']},
            'description': {'type': ['string', 'null']},
            'shutdown_mode': {'$ref': 'ServiceUpsShutdownmode'},
            'shutdown_timer': {'type': 'integer'},
            'monitor_user': {'type': 'string'},
            'monitor_password': {'type': 'password'},
            'allow_remote_connections': {'type': 'boolean'},
            'propagate_alerts': {'type': 'boolean'},
            'powerdown': {'type': 'boolean'},
            'auxiliary': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('ServiceUpsMode', {
        'type': 'string',
        'enum': ['MASTER', 'SLAVE']
    })
    plugin.register_schema_definition('ServiceUpsShutdownmode', {
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
