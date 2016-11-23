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
import errno
import os
import psutil
import re
import netif
import bsd
import logging
import time

from threading import Event, Thread
from datastore import DatastoreException
from datetime import datetime
from dateutil import tz, parser
from freenas.dispatcher.rpc import (
    RpcException,
    SchemaHelper as h,
    accepts,
    description,
    returns,
    private
)
from lib.system import SubprocessException, system
from lib.freebsd import get_sysctl
from task import Provider, Task, TaskException, VerifyException, TaskAbortException, ValidationException, TaskDescription
from debug import AttachCommandOutput, AttachData

if '/usr/local/lib' not in sys.path:
    sys.path.append('/usr/local/lib')
from freenasOS import Configuration

KEYMAPS_INDEX = "/usr/share/syscons/keymaps/INDEX.keymaps"
ZONEINFO_DIR = "/usr/share/zoneinfo"
VERSION_FILE = "/etc/version"
logger = logging.getLogger('SystemInfoPlugin')


@description("Provides informations about the running system")
class SystemInfoProvider(Provider):
    def __init__(self):
        self.__version = None

    @accepts()
    @returns(h.array(str))
    def uname_full(self):
        return os.uname()

    @accepts()
    @returns(str)
    @description("Return the full version string, e.g. FreeNAS-8.1-r7794-amd64.")
    def version(self):
        if self.__version is None:
            # See #9113
            conf = Configuration.Configuration()
            manifest = conf.SystemManifest()
            if manifest:
                self.__version = manifest.Version()
            else:
                with open(VERSION_FILE) as fd:
                    self.__version = fd.read().strip()

        return self.__version

    @accepts()
    @returns({'type': 'array', 'items': {'type': 'number'}, 'maxItems': 3, 'minItems': 3})
    def load_avg(self):
        return list(os.getloadavg())

    @accepts()
    @returns(h.object(properties={
        'cpu_model': str,
        'cpu_cores': int,
        'cpu_clockrate': int,
        'memory_size': int,
        'vm_guest': h.one_of(str, None)
    }))
    def hardware(self):
        vm_guest = get_sysctl("kern.vm_guest")
        return {
            'cpu_model': get_sysctl("hw.model"),
            'cpu_cores': get_sysctl("hw.ncpu"),
            'cpu_clockrate': get_sysctl("hw.clockrate"),
            'memory_size': get_sysctl("hw.physmem"),
            'vm_guest': None if vm_guest == 'none' else vm_guest
        }

    @accepts()
    @returns(str)
    def host_uuid(self):
        return get_sysctl("kern.hostuuid")[:-1]


@description("Provides informations about general system settings")
class SystemGeneralProvider(Provider):

    @accepts()
    @returns(h.ref('system-general'))
    def get_config(self):
        return {
            'hostname': self.configstore.get('system.hostname'),
            'description': self.configstore.get('system.description'),
            'tags': self.configstore.get('system.tags'),
            'language': self.configstore.get('system.language'),
            'timezone': self.configstore.get('system.timezone'),
            'syslog_server': self.configstore.get('system.syslog_server'),
            'console_keymap': self.configstore.get('system.console.keymap')
        }

    @accepts()
    @returns(h.array(h.array(str)))
    def keymaps(self):
        if not os.path.exists(KEYMAPS_INDEX):
            return []

        rv = []
        with open(KEYMAPS_INDEX, 'r', encoding='utf-8', errors='ignore') as f:
            d = f.read()
        fnd = re.findall(r'^(?P<name>[^#\s]+?)\.kbd:en:(?P<desc>.+)$', d, re.M)
        for name, desc in fnd:
            rv.append((name, desc))
        return rv

    @accepts()
    @returns(h.array(str))
    def timezones(self):
        result = []
        for root, _, files in os.walk(ZONEINFO_DIR):
            for f in files:
                if f in ('zone.tab', 'posixrules'):
                    continue

                result.append(os.path.join(root, f).replace(ZONEINFO_DIR + '/', ''))

        return sorted(result)

    @private
    @accepts(str, str)
    @returns(str)
    def cowsay(self, line, cow_file='default'):
        if cow_file != 'default' and os.path.exists(cow_file):
            return system('/usr/local/bin/cowsay', '-f', cow_file, '-s', line)
        else:
            return system('/usr/local/bin/cowsay', '-s', line)


@description("Provides informations about advanced system settings")
class SystemAdvancedProvider(Provider):

    @accepts()
    @returns(h.ref('system-advanced'))
    def get_config(self):
        cs = self.configstore
        return {
            'console_cli': cs.get('system.console.cli'),
            'console_screensaver': cs.get('system.console.screensaver'),
            'serial_console': cs.get('system.serial.console'),
            'serial_port': cs.get('system.serial.port'),
            'serial_speed': cs.get('system.serial.speed'),
            'powerd': cs.get('service.powerd.enable'),
            'swapondrive': cs.get('system.swapondrive'),
            'debugkernel': cs.get('system.debug.kernel'),
            'uploadcrash': cs.get('system.upload_crash'),
            'home_directory_root': cs.get('system.home_directory_root'),
            'motd': cs.get('system.motd'),
            'boot_scrub_internal': cs.get('system.boot_scrub_internal'),
            'periodic_notify_user': cs.get('system.periodic.notify_user'),
            'graphite_servers': cs.get('system.graphite_servers'),
            'freenas_token_lifetime': cs.get('peer.freenas.token_lifetime')
        }


@description("Provides informations about system time")
class SystemTimeProvider(Provider):

    @accepts()
    @returns(h.ref('system-time'))
    def get_config(self):
        boot_time = datetime.utcfromtimestamp(psutil.boot_time())
        return {
            'system_time': datetime.now(tz=tz.tzlocal()),
            'boot_time': boot_time,
            'uptime': (datetime.utcnow() - boot_time).total_seconds(),
            'timezone': time.tzname[time.daylight],
        }


@description("Provides informations about UI system settings")
class SystemUIProvider(Provider):

    @accepts()
    @returns(h.ref('system-ui'))
    def get_config(self):

        protocol = []
        if self.configstore.get('service.nginx.http.enable'):
            protocol.append('HTTP')
        if self.configstore.get('service.nginx.https.enable'):
            protocol.append('HTTPS')

        return {
            'webui_protocol': protocol,
            'webui_listen': self.configstore.get('service.nginx.listen'),
            'webui_http_port': self.configstore.get('service.nginx.http.port'),
            'webui_http_redirect_https': self.configstore.get('service.nginx.http.redirect_https'),
            'webui_https_certificate': self.configstore.get('service.nginx.https.certificate'),
            'webui_https_port': self.configstore.get('service.nginx.https.port')
        }


@description("Configures general system settings")
@accepts(h.ref('system-general'))
class SystemGeneralConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return "Configuring general system settings"

    def describe(self, props):
        return TaskDescription("Configuring general system settings")

    def verify(self, props):
        errors = ValidationException()
        if 'timezone' in props:
            timezones = self.dispatcher.call_sync('system.general.timezones')
            if props['timezone'] not in timezones:
                errors.add((0, 'timezone'), 'Invalid timezone: {0}'.format(props['timezone']))

        if errors:
            raise errors

        return ['system']

    def run(self, props):
        if 'hostname' in props:
            netif.set_hostname(props['hostname'])

        if 'description' in props:
            self.configstore.set('system.description', props['description'])

        if 'tags' in props:
            self.configstore.set('system.tags', props['tags'])

        if 'language' in props:
            self.configstore.set('system.language', props['language'])

        if 'timezone' in props:
            self.configstore.set('system.timezone', props['timezone'])
            os.environ['TZ'] = props['timezone']

        if 'console_keymap' in props:
            self.configstore.set(
                'system.console.keymap',
                props['console_keymap'],
            )

        syslog_changed = False
        if 'syslog_server' in props:
            self.configstore.set('system.syslog_server', props['syslog_server'])
            syslog_changed = True

        try:
            self.dispatcher.call_sync('etcd.generation.generate_group', 'localtime')
            if syslog_changed:
                self.dispatcher.call_sync('etcd.generation.generate_group', 'syslog')
                self.dispatcher.call_sync('service.reload', 'syslog')
        except RpcException as e:
            raise TaskException(
                errno.ENXIO,
                'Cannot reconfigure system: {0}'.format(str(e),)
            )

        self.dispatcher.dispatch_event('system.general.changed', {
            'operation': 'update',
        })


@description("Configures advanced system settings")
@accepts(h.ref('system-advanced'))
class SystemAdvancedConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring advanced system settings'

    def describe(self, props):
        return TaskDescription('Configuring advanced system settings')

    def verify(self, props):
        if 'periodic_notify_user' in props:
            if props['periodic_notify_user'] in range(1, 1000):
                raise VerifyException(errno.EINVAL,
                                      '"periodic_notify_user" should not be value inside range 1..999')

        return ['system']

    def run(self, props):
        try:
            cs = self.configstore

            console = False
            loader = False
            rc = False

            if 'console_cli' in props:
                cs.set('system.console.cli', props['console_cli'])
                console = True

            if 'console_screensaver' in props:
                cs.set('system.console.screensaver', props['console_screensaver'])
                if props['console_screensaver']:
                    try:
                        system('kldload', 'daemon_saver')
                    except SubprocessException:
                        pass
                else:
                    try:
                        system('kldunload', 'daemon_saver')
                    except SubprocessException:
                        pass
                rc = True

            if 'serial_console' in props:
                cs.set('system.serial.console', props['serial_console'])
                loader = True
                console = True

            if 'serial_port' in props:
                cs.set('system.serial.port', props['serial_port'])
                loader = True
                console = True

            if 'serial_speed' in props:
                cs.set('system.serial.speed', props['serial_speed'])
                loader = True
                console = True

            if 'powerd' in props:
                cs.set('service.powerd.enable', props['powerd'])
                self.dispatcher.call_sync('service.apply_state', 'powerd')
                rc = True

            if 'swapondrive' in props:
                cs.set('system.swapondrive', props['swapondrive'])

            if 'debugkernel' in props:
                cs.set('system.debug.kernel', props['debugkernel'])
                loader = True

            if 'uploadcrash' in props:
                cs.set('system.upload_crash', props['uploadcrash'])
                rc = True

            if 'home_directory_root' in props:
                self.configstore.set('system.home_directory_root', props['home_directory_root'])

            if 'motd' in props:
                cs.set('system.motd', props['motd'])
                self.dispatcher.call_sync('etcd.generation.generate_file', 'motd')

            if 'boot_scrub_internal' in props:
                cs.set('system.boot_scrub_internal', props['boot_scrub_internal'])

            if 'periodic_notify_user' in props:
                cs.set('system.periodic.notify_user', props['periodic_notify_user'])
                self.dispatcher.call_sync('etcd.generation.generate_group', 'periodic')

            if 'graphite_servers' in props:
                cs.set('system.graphite_servers', props['graphite_servers'])
                self.dispatcher.call_sync('etcd.generation.generate_group', 'collectd')
                self.dispatcher.call_sync('service.restart', 'collectd')

            if 'freenas_token_lifetime' in props:
                cs.set('peer.freenas.token_lifetime', props['freenas_token_lifetime'])

            if console:
                self.dispatcher.call_sync('etcd.generation.generate_group', 'console')

            if loader:
                self.dispatcher.call_sync('etcd.generation.generate_group', 'loader')

            if rc:
                self.dispatcher.call_sync('etcd.generation.generate_group', 'services')
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot configure system advanced: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure system: {0}'.format(str(e)))

        self.dispatcher.dispatch_event('system.advanced.changed', {
            'operation': 'update',
        })


@description("Configures the System UI settings")
@accepts(h.ref('system-ui'))
class SystemUIConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring System UI settings'

    def describe(self, props):
        return TaskDescription('Configuring System UI settings')

    def verify(self, props):
        return ['system']

    def run(self, props):
        webui_protocol = props.get('webui_protocol', [])
        if webui_protocol:
            self.configstore.set(
                'service.nginx.http.enable',
                True if 'HTTP' in webui_protocol else False,
            )
            self.configstore.set(
                'service.nginx.https.enable',
                True if 'HTTPS' in webui_protocol else False,
            )
        if 'webui_listen' in props:
            self.configstore.set('service.nginx.listen', props['webui_listen'])

        if 'webui_http_port' in props:
            self.configstore.set('service.nginx.http.port', props['webui_http_port'])

        if 'webui_http_redirect_https' in props:
            self.configstore.set('service.nginx.http.redirect_https', props['webui_http_redirect_https'])

        if 'webui_https_certificate' in props:
            if not self.dispatcher.call_sync('crypto.certificate.query',
                                            [('type', '!=', 'CERT_CSR'), ('id', '=', props['webui_https_certificate'])],
                                             {'count': True}):
                raise TaskException(errno.ENOENT, 'Certificate id : {0} does not exist'.format(
                    props['webui_https_certificate']))
            else:
                self.configstore.set('service.nginx.https.certificate', props['webui_https_certificate'])

        if 'webui_https_port' in props:
            self.configstore.set('service.nginx.https.port', props['webui_https_port'])

        if self.configstore.get('service.nginx.https.enable', False) and not self.configstore.get(
                'service.nginx.https.certificate', False):
            raise TaskException(errno.EINVAL, 'HTTPS protocol specified for UI without certificate')

        try:
            self.dispatcher.call_sync('etcd.generation.generate_group', 'nginx')
            self.dispatcher.call_sync('service.reload', 'nginx')
        except RpcException as e:
            raise TaskException(
                errno.ENXIO,
                'Cannot reconfigure system UI: {0}'.format(str(e))
            )

        self.dispatcher.dispatch_event('system.ui.changed', {
            'operation': 'update',
            'ids': ['system.ui'],
        })


@accepts(h.all_of(
    h.ref('system-time'),
    h.forbidden('boot_time', 'uptime')
))
@description("Configures system time")
class SystemTimeConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Configuring system time'

    def describe(self, props):
        return TaskDescription('Configuring system time')

    def verify(self, props):
        return ['system']

    def run(self, props):
        if 'system_time' in props:
            timestamp = time.mktime(parser.parse(props['system_time']))
            bsd.clock_settime(bsd.ClockType.REALTIME, timestamp)

        if 'timezone' in props:
            self.configstore.set('system.timezone', props['timezone'])
            try:
                self.dispatcher.call_sync('etcd.generation.generate_group', 'localtime')
            except RpcException as e:
                raise TaskException(
                    errno.ENXIO,
                    'Cannot reconfigure system time: {0}'.format(str(e))
                )


@accepts(h.any_of(int, None))
@description("Reboots the System")
class SystemRebootTask(Task):
    def __init__(self, dispatcher, datastore):
        super(SystemRebootTask, self).__init__(dispatcher, datastore)
        self.finish_event = Event()
        self.abort_flag = False

    @classmethod
    def early_describe(cls):
        return 'Rebooting system'

    def describe(self, delay=None):
        return TaskDescription('Rebooting system with delay {delay} seconds', delay=delay or 0)

    def verify(self, delay=None):
        return ['root']

    def reboot_now(self):
        time.sleep(1)
        system('/sbin/shutdown', '-r', 'now')

    def run(self, delay=None):
        if delay:
            self.finish_event.wait(delay)

        if self.abort_flag:
            raise TaskAbortException(errno.EINTR, "User invoked task.abort")

        self.dispatcher.dispatch_event('power.changed', {
            'operation': 'REBOOT',
        })

        self.dispatcher.call_sync('alert.emit', {
            'class': 'SystemReboot',
            'user': self.user,
            'title': 'System reboot',
            'description': 'System has been rebooted by {0}'.format(self.user)
        })

        t = Thread(target=self.reboot_now, daemon=True)
        t.start()

    def abort(self):
        self.abort_flag = True
        self.finish_event.set()
        return True


@accepts(h.any_of(int, None))
@description("Shuts the system down")
class SystemHaltTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Shutting the system down'

    def describe(self):
        return TaskDescription('Shutting the system down')

    def verify(self):
        return ['root']

    def shutdown_now(self):
        time.sleep(1)
        system('/sbin/shutdown', '-p', 'now')

    def run(self):
        self.dispatcher.dispatch_event('power.changed', {
            'operation': 'SHUTDOWN',
        })

        self.dispatcher.call_sync('alert.emit', {
            'class': 'SystemShutdown',
            'user': self.user,
            'title': 'System shutdown',
            'description': 'System has been shut down by {0}'.format(self.user)
        })

        t = Thread(target=self.shutdown_now, daemon=True)
        t.start()


def collect_debug(dispatcher):
    yield AttachCommandOutput('uptime', ['/usr/bin/uptime'])
    yield AttachCommandOutput('date', ['/bin/date'])
    yield AttachCommandOutput('process-list', ['/bin/ps', 'auxww'])
    yield AttachCommandOutput('mountpoints', ['/sbin/mount'])
    yield AttachCommandOutput('df-h', ['/bin/df', '-h'])
    yield AttachCommandOutput('swapinfo', ['/usr/sbin/swapinfo', '-h'])
    yield AttachCommandOutput('kldstat', ['/sbin/kldstat'])
    yield AttachCommandOutput('dmesg', ['/sbin/dmesg', '-a'])
    yield AttachCommandOutput('procstat', ['/usr/bin/procstat', '-akk'])
    yield AttachCommandOutput('vmstat', ['/usr/bin/vmstat', '-i'])
    yield AttachData('version', dispatcher.call_sync('system.info.version'))


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):
    def on_hostname_change(args):
        if 'hostname' not in args:
            return

        if args.get('jid') != 0:
            return

        dispatcher.configstore.set('system.hostname', args['hostname'])
        dispatcher.call_sync('service.restart', 'mdns')
        dispatcher.dispatch_event('system.general.changed', {
            'operation': 'update',
        })

    def on_system_timezone_change(args):
        logger.warning('Setting time zone to {0}'.format(args.get('timezone')))
        os.environ['TZ'] = args.get('timezone')
        time.tzset()

    # Register schemas
    plugin.register_schema_definition('system-advanced', {
        'type': 'object',
        'properties': {
            'console_cli': {'type': 'boolean'},
            'console_screensaver': {'type': 'boolean'},
            'serial_console': {'type': 'boolean'},
            'serial_port': {'type': 'string'},
            'serial_speed': {'$ref': 'system-advanced-serialspeed'},
            'powerd': {'type': 'boolean'},
            'swapondrive': {'type': 'integer'},
            'debugkernel': {'type': 'boolean'},
            'uploadcrash': {'type': 'boolean'},
            'home_directory_root': {'type': ['string', 'null']},
            'motd': {'type': 'string'},
            'boot_scrub_internal': {'type': 'integer'},
            'periodic_notify_user': {'type': 'integer'},
            'graphite_servers': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'freenas_token_lifetime': {'type': 'integer'}
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('system-advanced-serialspeed', {
        'type': 'integer',
        'enum': [110, 300, 600, 1200, 2400, 4800,
                 9600, 14400, 19200, 38400, 57600, 115200]
    })

    plugin.register_schema_definition('system-general', {
        'type': 'object',
        'properties': {
            'hostname': {'type': 'string'},
            'description': {'type': 'string'},
            'tags': {
                'type': 'array',
                'items': {'type': 'string'}
            },
            'language': {'type': 'string'},
            'timezone': {'type': 'string'},
            'console_keymap': {'type': 'string'},
            'syslog_server': {'type': ['string', 'null']},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('system-ui', {
        'type': 'object',
        'properties': {
            'webui_protocol': {
                'type': ['array'],
                'items': {'$ref': 'system-ui-webuiprotocol-items'}
            },
            'webui_listen': {
                'type': ['array'],
                'items': {'$ref': 'ip-address'},
            },
            'webui_http_redirect_https': {'type': 'boolean'},
            'webui_http_port': {'type': 'integer'},
            'webui_https_certificate': {'type': ['string', 'null']},
            'webui_https_port': {'type': 'integer'},
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('system-ui-webuiprotocol-items', {
        'type': 'string',
        'enum': ['HTTP', 'HTTPS'],
    })

    plugin.register_schema_definition('system-time', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'system_time': {'type': 'datetime'},
            'boot_time': {'type': 'datetime'},
            'uptime': {'type': 'number'},
            'timezone': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('power-changed', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'operation': {'$ref': 'power-changed-operation'},
        }
    })

    plugin.register_schema_definition('power-changed-operation', {
        'type': 'string',
        'enum': ['SHUTDOWN', 'REBOOT']
    })

    # Register event handlers
    plugin.register_event_handler('system.hostname.change', on_hostname_change)
    plugin.register_event_handler('system.timezone.change', on_system_timezone_change)

    # Register Event Types
    plugin.register_event_type('system.general.changed')
    plugin.register_event_type('system.advanced.changed')
    plugin.register_event_type('system.ui.changed')
    plugin.register_event_type('power.changed', schema=h.ref('power-changed'))

    # Register providers
    plugin.register_provider("system.advanced", SystemAdvancedProvider)
    plugin.register_provider("system.general", SystemGeneralProvider)
    plugin.register_provider("system.info", SystemInfoProvider)
    plugin.register_provider("system.time", SystemTimeProvider)
    plugin.register_provider("system.ui", SystemUIProvider)

    # Register task handlers
    plugin.register_task_handler("system.advanced.update", SystemAdvancedConfigureTask)
    plugin.register_task_handler("system.general.update", SystemGeneralConfigureTask)
    plugin.register_task_handler("system.ui.update", SystemUIConfigureTask)
    plugin.register_task_handler("system.time.update", SystemTimeConfigureTask)
    plugin.register_task_handler("system.shutdown", SystemHaltTask)
    plugin.register_task_handler("system.reboot", SystemRebootTask)

    # Register debug hook
    plugin.register_debug_hook(collect_debug)

    # Set initial hostname
    netif.set_hostname(dispatcher.configstore.get('system.hostname'))
