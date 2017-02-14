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

import os
import re
import netif
import time
import io
import fnmatch
import uuid
import hashlib
import logging
import contextlib
import usb1
from xml.etree import ElementTree
from bsd import geom
from bsd import devinfo
from bsd import sysctl
from event import EventSource
from task import Provider
from debug import AttachCommandOutput
from freenas.dispatcher.rpc import accepts, returns, description
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h
from gevent import socket
from lib.freebsd import get_sysctl
from lib.system import system, SubprocessException
from freenas.utils import exclude, query as q


HOSTUUID_BLACKLIST = [
    '00000000-0000-0000-0000-000000000000',
    '00020003-0004-0005-0006-000700080009',
    '03000200-0400-0500-0006-000700080009',
    '07090201-0103-0301-0807-060504030201',
    '11111111-1111-1111-1111-111111111111',
    '11111111-2222-3333-4444-555555555555',
    '4c4c4544-0000-2010-8020-80c04f202020',
    '58585858-5858-5858-5858-585858585858',
    '890e2d14-cacd-45d1-ae66-bc80e8bfeb0f',
    '8e275844-178f-44a8-aceb-a7d7e5178c63',
    'dc698397-fa54-4cf2-82c8-b1b5307a6a7f',
    'fefefefe-fefe-fefe-fefe-fefefefefefe',
    '*-ffff-ffff-ffff-ffffffffffff'
]


logger = logging.getLogger('DevdPlugin')


@description("Provides information about devices installed in the system")
class DeviceInfoProvider(Provider):
    @description("Returns list of available device classes")
    @returns(h.array(str))
    def get_classes(self):
        return [
            "disk",
            "network",
            "cpu",
            "usb",
            "serial_port"
        ]

    @description("Returns list of devices from given class")
    @accepts(str)
    @returns(h.any_of(
        h.ref('DiskDevice'),
        h.ref('NetworkDevice'),
        h.ref('CpuDevice'),
        h.ref('SerialPortDevice'),
        h.ref('UsbDevice')
    ))
    def get_devices(self, dev_class):
        method = "_get_class_{0}".format(dev_class)
        if hasattr(self, method):
            return getattr(self, method)()

        return None

    def _get_class_disk(self):
        result = []
        geom.scan()
        for child in geom.class_by_name('DISK').geoms:
            result.append({
                "path": os.path.join("/dev", child.name),
                "name": child.name,
                "mediasize": child.provider.mediasize,
                "description": child.provider.config['descr']
            })

        return result

    def _get_class_multipath(self):
        result = []
        geom.scan()
        cls = geom.class_by_name('MULTIPATH')
        if not cls:
            return []

        for child in cls.geoms:
            result.append({
                "path": os.path.join("/dev", child.name),
                "name": child.name,
                "mediasize": child.provider.mediasize,
                "members": [c.provider.name for c in child.consumers]
            })

        return result

    def _get_class_network(self):
        result = []
        for i in list(netif.list_interfaces().keys()):
            if i.startswith(tuple(netif.CLONED_PREFIXES)):
                continue

            try:
                desc = get_sysctl(re.sub('(\w+)([0-9]+)', 'dev.\\1.\\2.%desc', i))
                result.append({
                    'name': i,
                    'description': desc
                })
            except FileNotFoundError:
                continue

        return result

    def _get_class_serial_port(self):
        result = []
        for devices in devinfo.DevInfo().resource_managers['I/O ports'].values():
            for dev in devices:
                if not dev.name.startswith('uart'):
                    continue
                result.append({
                    'name': dev.name,
                    'description': dev.desc,
                    'drivername': dev.drivername,
                    'location': dev.location,
                    'start': hex(dev.start),
                    'size': dev.size
                })

        return result

    def _get_class_cpu(self):
        result = []
        ncpus = get_sysctl('hw.ncpu')
        model = get_sysctl('hw.model').strip('\x00')
        for i in range(0, ncpus):
            freq = None
            temp = None

            with contextlib.suppress(OSError):
                freq = get_sysctl('dev.cpu.{0}.freq'.format(i)),

            with contextlib.suppress(OSError):
                temp = get_sysctl('dev.cpu.{0}.temperature'.format(i))

            result.append({
                'name': model,
                'freq': freq,
                'temperature': temp
            })

        return result

    def _get_class_usb(self):
        result = []
        context = usb1.USBContext()

        for device in context.getDeviceList():
            result.append({
                'bus': device.getBusNumber(),
                'address': device.getDeviceAddress(),
                'manufacturer': device.getManufacturer(),
                'product': device.getProduct(),
                'vid': device.getVendorID(),
                'pid': device.getProductID(),
                'class': device.getDeviceClass()
            })

        context.exit()
        return result


class DMIDataProvider(Provider):
    def __init__(self):
        try:
            out, err = system('/usr/local/sbin/dmidecode', '-q')
        except SubprocessException:
            self._result = {}
            return

        result = {}
        section = None
        subsection = None

        for line in out.splitlines():
            level = len(line) - len(line.lstrip('\t'))

            if not line.strip():
                continue

            if level == 0:
                subsection = None
                section = {}
                result[line.strip()] = section
                continue

            if level == 1:
                subsection = None
                if section is None:
                    continue

                try:
                    key, value = line.split(':', maxsplit=1)
                    if value.strip():
                        section[key.strip()] = value.strip()
                    else:
                        subsection = []
                        section[key.strip()] = subsection
                except ValueError:
                    logger.warning('Cannot parse line from DMI data at level 1: {0}'.format(line))

                continue

            if level == 2:
                if subsection is None:
                    continue

                subsection.append(line.strip())

        self._result = result

    def get(self):
        return self._result


class DevdEventSource(EventSource):
    class DevdEvent(dict):
        def __init__(self, kind):
            self.kind = kind
            super(DevdEventSource.DevdEvent, self).__init__()

    def __init__(self, dispatcher):
        super(DevdEventSource, self).__init__(dispatcher)
        self.socket = None
        self.register_event_type("system.device.attached")
        self.register_event_type("system.device.detached")
        self.register_event_type("system.device.changed")
        self.register_event_type("system.network.interface.attached")
        self.register_event_type("system.network.interface.detached")
        self.register_event_type("system.network.interface.link_up")
        self.register_event_type("system.network.interface.link_down")
        self.register_event_type("fs.zfs.scrub.start")
        self.register_event_type("fs.zfs.scrub.finish")
        self.register_event_type("fs.zfs.scrub.aborted")
        self.register_event_type("fs.zfs.resilver.started")
        self.register_event_type("fs.zfs.resilver.finished")
        self.register_event_type("fs.zfs.pool.created")
        self.register_event_type("fs.zfs.pool.destroyed")
        self.register_event_type("fs.zfs.pool.updated")
        self.register_event_type("fs.zfs.vdev.created")
        self.register_event_type("fs.zfs.vdev.updated")
        self.register_event_type("fs.zfs.vdev.removed")
        self.register_event_type("fs.zfs.dataset.created")
        self.register_event_type("fs.zfs.dataset.deleted")
        self.register_event_type("fs.zfs.dataset.renamed")
        self.register_event_type("fs.zfs.snapshot.cloned")
        self.register_event_type("iscsi.session.update")

    def __tokenize(self, buffer):
        try:
            tree = ElementTree.fromstring(buffer)
        except ElementTree.ParseError:
            return None

        ret = self.DevdEvent(tree.tag)
        for i in tree:
            ret[i.tag] = i.text

        return ret

    def __process_devfs(self, args):
        if args["subsystem"] == "CDEV":
            params = {
                "name": args["cdev"],
                "path": os.path.join("/dev", args["cdev"])
            }

            if args["type"] == "CREATE":
                params["description"] = "Device {0} attached".format(args["cdev"])
                self.emit_event("system.device.attached", **params)

            if args["type"] == "DESTROY":
                params["description"] = "Device {0} detached".format(args["cdev"])
                self.emit_event("system.device.detached", **params)

            if args["type"] == "MEDIACHANGE":
                params["description"] = "Device {0} media changed".format(args["cdev"])
                self.emit_event("system.device.mediachange", **params)

    def __process_ifnet(self, args):
        params = {
            "interface": args["subsystem"]
        }

    def __process_system(self, args):
        if args["subsystem"] == "HOSTNAME":
            if args["type"] == "CHANGE":
                params = exclude(args, "system", "subsystem", "type")
                params["description"] = "System hostname changed"
                params["jid"] = int(args["jid"])
                self.emit_event("system.hostname.change", **params)

        if args["subsystem"] == "VFS":
            if args["type"] == "MOUNT":
                params = exclude(args, "system", "subsystem", "type")
                params["description"] = "Filesystem {0} mounted".format(args["path"])
                self.emit_event("system.fs.mounted", **params)

            if args["type"] == "UNMOUNT":
                params = exclude(args, "system", "subsystem", "type")
                params["description"] = "Filesystem {0} unmounted".format(args["path"])
                self.emit_event("system.fs.unmounted", **params)

    def __process_zfs(self, args):
        event_mapping = {
            "misc.fs.zfs.scrub_start": ("fs.zfs.scrub.started", "Scrub on volume {0} started"),
            "misc.fs.zfs.scrub_finish": ("fs.zfs.scrub.finished", "Scrub on volume {0} finished"),
            "misc.fs.zfs.scrub_abort": ("fs.zfs.scrub.aborted", "Scrub on volume {0} aborted"),
            "misc.fs.zfs.resilver_start": ("fs.zfs.resilver.started", "Resilver on volume {0} started"),
            "misc.fs.zfs.resilver_finish": ("fs.zfs.resilver.finished", "Resilver on volume {0} finished"),
            "misc.fs.zfs.pool_create": ("fs.zfs.pool.created", "Pool {0} created"),
            "misc.fs.zfs.pool_import": ("fs.zfs.pool.imported", "Pool {0} imported"),
            "misc.fs.zfs.pool_destroy": ("fs.zfs.pool.destroyed", "Pool {0} destroyed"),
            "misc.fs.zfs.pool_setprop": ("fs.zfs.pool.setprop", "Property on pool {0} changed"),
            "misc.fs.zfs.pool_reguid": ("fs.zfs.pool.setprop", "Pool {0} GUID changed"),
            "misc.fs.zfs.config_sync": ("fs.zfs.pool.config_sync", "Pool {0} config changed"),
            "misc.fs.zfs.dataset_create": ("fs.zfs.dataset.created", "Dataset on pool {0} created"),
            "misc.fs.zfs.dataset_delete": ("fs.zfs.dataset.deleted", "Dataset on pool {0} deleted"),
            "misc.fs.zfs.dataset_rename": ("fs.zfs.dataset.renamed", "Dataset on pool {0} renamed"),
            "misc.fs.zfs.dataset_setprop": ("fs.zfs.dataset.setprop", "Property of dataset on pool {0} changed"),
            "misc.fs.zfs.snapshot_clone": ("fs.zfs.snapshot.cloned", "Snapshot {0} cloned"),
            "misc.fs.zfs.vdev_add": ("fs.zfs.vdev.created", "Vdev on pool {0} created"),
            "misc.fs.zfs.vdev_attach": ("fs.zfs.vdev.attached", "Vdev on pool {0} attached"),
            "misc.fs.zfs.vdev_remove": ("fs.zfs.vdev.removed", "Vdev on pool {0} removed"),
            "misc.fs.zfs.vdev_statechange": ("fs.zfs.vdev.state_changed", "Vdev on pool {0} status changed")
        }

        if args["type"] not in event_mapping:
            return

        ev_type = args.pop("type")
        pool_name = args.pop("pool_name", None)

        params = {
            "pool": pool_name,
            "guid": str(args.pop("pool_guid", None)),
            "description": event_mapping[ev_type][1].format(pool_name)
        }

        params.update(args)
        self.emit_event(event_mapping[ev_type][0], **params)

    def __process_iscsi(self, args):
        if args['subsystem'] == 'SESSION' and args['type'] == 'UPDATE':
            self.emit_event('iscsi.session.update', **exclude(args, "system", "subsystem", "type"))

    def run(self):
        while True:
            try:
                self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                self.socket.connect("/var/run/devd.xml.seqpacket.pipe")
                
                while True:
                    line = self.socket.recv(8192)
                    if line is None:
                        # Connection closed - we need to reconnect
                        # return
                        raise OSError('Connection closed')

                    event = self.__tokenize(line.strip(b'\x00').decode('utf-8', 'replace'))
                    if not event:
                        # WTF
                        continue
                        
                    if "system" not in event:
                        # WTF
                        continue

                    if event["system"] == "DEVFS":
                        self.__process_devfs(event)

                    if event["system"] == "IFNET":
                        self.__process_ifnet(event)

                    if event["system"] == "ZFS":
                        self.__process_zfs(event)

                    if event["system"] == "ISCSI":
                        self.__process_iscsi(event)

                    if event["system"] == "SYSTEM":
                        self.__process_system(event)

            except OSError as err:
                # sleep for a half a second and retry
                self.dispatcher.logger.info('/var/run/devd.pipe read error: {0}'.format(str(err)))
                self.dispatcher.logger.info('retrying in 1s')
                time.sleep(1)

            self.socket.close()


def collect_debug(dispatcher):
    yield AttachCommandOutput('dmidecode', ['/usr/local/sbin/dmidecode'])
    yield AttachCommandOutput('pciconf', ['/usr/sbin/pciconf', '-lv'])
    yield AttachCommandOutput('devinfo', ['/usr/sbin/devinfo', '-rv'])


def _depends():
    return ['ServiceManagePlugin']


def _init(dispatcher, plugin):
    def on_service_started(args):
        if args['name'] == 'devd':
            # devd is running, kick in DevdEventSource
            plugin.register_event_source('system.device', DevdEventSource)
            plugin.unregister_event_handler(
                'service.started', on_service_started)

    plugin.register_schema_definition('DiskDevice', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'mediasize': {'type': 'integer'},
            'description': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('NetworkDevice', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'description': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('CpuDevice', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'description': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('SerialPortDevice', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'drivername': {'type': 'string'},
            'location': {'type': 'string'},
            'start': {'type': 'string'},
            'size': {'type': 'string'},
        }
    })

    plugin.register_schema_definition('UsbDevice', {
        'type': 'object',
        'properties': {
            'bus': {'type': 'integer'},
            'address': {'type': 'integer'},
            'manufacturer': {'type': 'string'},
            'product': {'type': 'string'},
            'class': {'type': 'integer'},
            'vid': {'type': 'integer'},
            'pid': {'type': 'integer'}
        }
    })

    plugin.register_event_source('system.device', DevdEventSource)
    plugin.register_provider('system.device', DeviceInfoProvider)
    plugin.register_provider('system.dmi', DMIDataProvider)

    # Set kern.hostuuid to the correct thing
    dmi = dispatcher.call_sync('system.dmi.get')
    hostuuid = q.get(dmi, 'System Information.UUID')

    if hostuuid:
        hostuuid = hostuuid.lower()
        logger.info('Hardware system UUID: {0}'.format(hostuuid))

    if not hostuuid or any(fnmatch.fnmatch(hostuuid, p) for p in HOSTUUID_BLACKLIST):
        # Bad uuid. Check for a saved one
        hostuuid = dispatcher.configstore.get('system.hostuuid')
        if not hostuuid:
            # No SMBIOS hostuuid and no saved one
            hostuuid = str(uuid.uuid4())

    hostid = int.from_bytes(hashlib.md5(hostuuid.encode('ascii')).digest()[:4], byteorder='little')
    dispatcher.configstore.set('system.hostuuid', hostuuid)
    sysctl.sysctlbyname('kern.hostuuid', new=hostuuid)
    sysctl.sysctlbyname('kern.hostid', new=hostid)
