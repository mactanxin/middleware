#
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

import ipaddress
import errno
import os
import copy
import random
import gzip
import uuid
import pygit2
import urllib.request
import urllib.parse
import urllib.error
import shutil
import tarfile
import logging
import datetime
from bsd import sysctl
from task import Provider, Task, ProgressTask, VerifyException, TaskException, query, TaskWarning, TaskDescription
from task import ValidationException
from datastore.config import ConfigNode
from freenas.dispatcher.jsonenc import loads, dumps
from freenas.dispatcher.rpc import RpcException, generator
from freenas.dispatcher.rpc import SchemaHelper as h, description, accepts, returns, private
from freenas.utils import first_or_default, normalize, deep_update, process_template, in_directory, sha256, query as q
from utils import save_config, load_config, delete_config
from freenas.utils.decorators import throttle
from freenas.utils.copytree import copytree
from debug import AttachData, AttachDirectory, AttachCommandOutput


VM_OUI = '00:a0:98'  # NetApp
BLOCKSIZE = 65536


logger = logging.getLogger(__name__)


@description('Provides information about VMs')
class VMProvider(Provider):
    @query('vm')
    @generator
    def query(self, filter=None, params=None):
        def extend(obj):
            obj['status'] = self.dispatcher.call_sync('containerd.management.get_status', obj['id'])
            root = self.dispatcher.call_sync('vm.get_vm_root', obj['id'])
            if os.path.isdir(root):
                readme = get_readme(root)
                if readme:
                    with open(readme, 'r') as readme_file:
                        obj['config']['readme'] = readme_file.read()
            return obj

        return q.query(
            self.datastore.query_stream('vms', callback=extend),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @private
    @accepts(str)
    @returns(h.one_of(str, None))
    def get_vm_root(self, vm_id):
        vm = self.datastore.get_by_id('vms', vm_id)
        if not vm:
            return None

        return os.path.join(self.dispatcher.call_sync('volume.get_volumes_root'), self.get_dataset(vm_id))

    @private
    @accepts(str)
    @returns(str)
    def get_dataset(self, vm_id):
        vm = self.datastore.get_by_id('vms', vm_id)
        return os.path.join(vm['target'], 'vm', vm['name'])

    @private
    @accepts(str, str)
    @returns(h.one_of(str, None))
    def get_disk_path(self, vm_id, disk_name):
        vm = self.datastore.get_by_id('vms', vm_id)
        if not vm:
            return None

        disk = first_or_default(lambda d: d['name'] == disk_name, vm['devices'])
        if not disk:
            return None

        if disk['type'] == 'DISK':
            return os.path.join('/dev/zvol', vm['target'], 'vm', vm['name'], disk_name)

        if disk['type'] == 'CDROM':
            path = disk['properties']['path']
            if os.path.isabs(path):
                return path
            else:
                return os.path.join(self.dispatcher.call_sync('vm.get_vm_root', vm_id), path)

    @private
    @accepts(str, str)
    @returns(h.one_of(str, None))
    def get_volume_path(self, vm_id, volume_name):
        vm = self.datastore.get_by_id('vms', vm_id)
        if not vm:
            return None

        vol = first_or_default(lambda v: v['name'] == volume_name, vm['devices'])
        if not vol:
            return None

        if vol['properties'].get('auto'):
            return os.path.join(self.get_vm_root(vm_id), vol['name'])

        return vol['properties']['destination']

    @private
    @description("Get VMs dependent on provided filesystem path")
    @accepts(str, bool, bool)
    @returns(h.array(h.ref('vm')))
    def get_dependencies(self, path, enabled_only=True, recursive=True):
        result = []

        if enabled_only:
            vms = self.datastore.query_stream('vms', ('enabled', '=', True))
        else:
            vms = self.datastore.query_stream('vms')

        for i in vms:
            target_path = self.get_vm_root(i['id'])
            if recursive:
                if in_directory(target_path, path):
                    result.append(i)
            else:
                if target_path == path:
                    result.append(i)

        return result

    @private
    @returns(str)
    def generate_mac(self):
        return VM_OUI + ':' + ':'.join('{0:02x}'.format(random.randint(0, 255)) for _ in range(0, 3))

    @private
    @accepts(str)
    @returns(h.array(str))
    def get_reserved_datasets(self, id):
        vm_snapshots = self.dispatcher.call_sync('vm.snapshot.query', [('parent.id', '=', id)])

        reserved_datasets = []
        for snap in vm_snapshots:
            reserved_datasets.extend(self.dispatcher.call_sync('vm.snapshot.get_dependent_datasets', snap['id']))

        return list(set(reserved_datasets))

    @private
    @accepts(str)
    @returns(h.array(str))
    def get_dependent_datasets(self, id):
        vm = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'single': True})
        if not vm:
            raise RpcException(errno.ENOENT, 'VM {0} does not exist'.format(id))

        devices = vm['devices']

        dataset = self.dispatcher.call_sync('vm.get_dataset', id)
        child_datasets = self.dispatcher.call_sync(
            'zfs.dataset.query',
            [('id', '~', '^({0}/)'.format(dataset))],
            {'select': 'name'}
        )
        dependent_datasets = [dataset]
        for d in child_datasets:
            if q.query(devices, ('name', '=', d.split('/')[-1]), ('type', 'in', ['DISK', 'VOLUME'])):
                dependent_datasets.append(d)

        return dependent_datasets

    @accepts(str)
    @returns(h.ref('vm-guest-info'))
    def get_guest_info(self, id):
        interfaces = self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'network.interfaces')
        loadavg = self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'system.loadavg')

        if interfaces and loadavg:
            return {
                'interfaces': interfaces,
                'load_avg': list(loadavg)
            }

    @accepts(str, str)
    @returns(h.object())
    def guest_ls(self, id, path):
        return list(self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'file.ls', path))

    @accepts(str, str)
    def guest_get(self, id, path):
        return self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'file.get', path)

    @accepts(str, str, h.array(str))
    def guest_exec(self, id, cmd, args):
        return self.dispatcher.call_sync('containerd.management.call_vmtools', id, 'system.exec', cmd, args)

    @accepts(str)
    @returns(str)
    def request_serial_console(self, id):
        return self.dispatcher.call_sync('containerd.console.request_console', id)

    @accepts(str)
    @returns(str)
    def request_webvnc_console(self, id):
        return self.dispatcher.call_sync('containerd.console.request_webvnc_console', id)

    @returns(h.ref('vm-hw-capabilites'))
    def get_hw_vm_capabilities(self):
        hw_capabilities = {'vtx_enabled': False, 'svm_features': False, 'unrestricted_guest': False}
        try:
            if sysctl.sysctlbyname('hw.vmm.vmx.initialized'):
                hw_capabilities['vtx_enabled'] = True

            if sysctl.sysctlbyname('hw.vmm.svm.features') > 0:
                hw_capabilities['svm_features'] = True

            if sysctl.sysctlbyname('hw.vmm.vmx.cap.unrestricted_guest'):
                hw_capabilities['unrestricted_guest'] = True
        except OSError:
            pass
        return hw_capabilities


@description('Provides information about VM snapshots')
class VMSnapshotProvider(Provider):
    @query('vm-snapshot')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('vm.snapshots', *(filter or []), **(params or {}))

    @private
    @accepts(str)
    @returns(h.array(str))
    def get_dependent_datasets(self, id):
        snapshot = self.dispatcher.call_sync('vm.snapshot.query', [('id', '=', id)], {'single': True})
        if not snapshot:
            raise RpcException(errno.ENOENT, 'VM snapshot {0} does not exist'.format(id))

        devices = snapshot['parent']['devices']

        dataset = self.dispatcher.call_sync('vm.get_dataset', snapshot['parent']['id'])
        child_datasets = self.dispatcher.call_sync(
            'zfs.dataset.query',
            [('id', '~', '^({0}/)'.format(dataset))],
            {'select': 'name'}
        )
        dependent_datasets = [dataset]
        for d in child_datasets:
            if q.query(devices, ('name', '=', d.split('/')[-1]), ('type', 'in', ['DISK', 'VOLUME'])):
                dependent_datasets.append(d)

        return dependent_datasets


@description('Provides information about VM templates')
class VMTemplateProvider(Provider):
    @query('vm')
    @generator
    def query(self, filter=None, params=None):
        fetch_lock = self.dispatcher.get_lock('vm_templates')
        try:
            fetch_lock.acquire(1)
            fetch_templates(self.dispatcher)
        except RpcException:
            pass
        finally:
            fetch_lock.release()

        templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')
        cache_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')
        templates = []
        for root, dirs, files in os.walk(templates_dir):
            if 'template.json' in files:
                with open(os.path.join(root, 'template.json'), encoding='utf-8') as template_file:
                    try:
                        template = loads(template_file.read())
                        readme = get_readme(root)
                        if readme:
                            with open(readme, 'r') as readme_file:
                                template['template']['readme'] = readme_file.read()
                        template['template']['path'] = root
                        template['template']['cached'] = False
                        template['template']['source'] = root.split('/')[-2]
                        if template['template']['source'] == 'ipfs':
                            with open(os.path.join(root, 'hash')) as ipfs_hash:
                                template['template']['hash'] = ipfs_hash.read()
                        if os.path.isdir(os.path.join(cache_dir, template['template']['name'])):
                            template['template']['cached'] = True
                        total_fetch_size = 0
                        for file in template['template']['fetch']:
                            total_fetch_size += file.get('size', 0)

                        template['template']['fetch_size'] = total_fetch_size

                        templates.append(template)
                    except ValueError:
                        pass

        return q.query(templates, *(filter or []), stream=True, **(params or {}))

    def get_allocation_size(self):
        cache_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')
        total_size = 0
        for root, _, files in os.walk(cache_dir):
            for file in files:
                total_size += os.path.getsize(os.path.join(root, file))

        return total_size


class VMConfigProvider(Provider):
    @returns(h.ref('vm-config'))
    def get_config(self):
        return ConfigNode('container', self.configstore).__getstate__()


@accepts(h.ref('vm-config'))
class VMConfigUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating VM subsystem configuration"

    def describe(self, updated_fields):
        return TaskDescription("Updating VM subsystem configuration")

    def verify(self, updated_fields):
        errors = ValidationException()
        if 'network' in updated_fields:
            for k, v in updated_fields['network'].items():
                try:
                    net = ipaddress.ip_network(v)
                    if net.prefixlen != 24:
                        raise ValueError('Prefix length must be 24')
                except ValueError as err:
                    errors.add((0, 'network', k), str(err))

        if errors:
            raise errors

        return ['system']

    def run(self, updated_fields):
        node = ConfigNode('container', self.configstore)
        node.update(updated_fields)
        self.add_warning(TaskWarning(errno.EBUSY, 'Changes will be effective on next reboot'))
        if 'additional_templates' in updated_fields:
            with self.dispatcher.get_lock('vm_templates'):
                valid_sources = updated_fields['additional_templates'] + ['github', 'ipfs']
                templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')
                for t in os.listdir(templates_dir):
                    if t not in valid_sources:
                        shutil.rmtree(os.path.join(templates_dir, t))


class VMBaseTask(ProgressTask):
    def __init__(self, dispatcher, datastore):
        super(VMBaseTask, self).__init__(dispatcher, datastore)
        self.vm_ds = None

    def init_dataset(self, vm):
        pool = vm['target']
        root_ds = os.path.join(pool, 'vm')
        self.vm_ds = os.path.join(root_ds, vm['name'])

        if not self.dispatcher.call_sync('zfs.dataset.query', [('name', '=', root_ds)], {'single': True}):
            # Create VM root
            self.join_subtasks(self.run_subtask('volume.dataset.create', {
                'volume': pool,
                'id': root_ds
            }))
        try:
            self.join_subtasks(self.run_subtask('volume.dataset.create', {
                'volume': pool,
                'id': self.vm_ds
            }))
        except RpcException:
            raise TaskException(
                errno.EACCES,
                'Dataset of the same name as {0} already exists. Maybe you meant to import an VM?'.format(self.vm_ds)
            )

    def init_files(self, vm, progress_cb=None):
        if progress_cb:
            progress_cb(0, 'Initializing VM files')
        template = vm.get('template')
        if not template:
            return

        dest_root = self.dispatcher.call_sync('volume.get_dataset_path', self.vm_ds)
        try:
            shutil.copy(os.path.join(template['path'], 'README.md'), dest_root)
        except OSError:
            pass

        if template.get('files'):
            source_root = os.path.join(template['path'], 'files')
            files_root = os.path.join(dest_root, 'files')

            os.mkdir(files_root)

            for root, dirs, files in os.walk(source_root):
                r = os.path.relpath(root, source_root)

                for f in files:
                    name, ext = os.path.splitext(f)
                    if ext == '.in':
                        process_template(os.path.join(root, f), os.path.join(files_root, r, name), **{
                            'VM_ROOT': dest_root
                        })
                    else:
                        shutil.copy(os.path.join(root, f), os.path.join(files_root, r, f))

                for d in dirs:
                    os.mkdir(os.path.join(files_root, r, d))

            if template.get('fetch'):
                for f in template['fetch']:
                    if f.get('dest'):
                        self.join_subtasks(self.run_subtask(
                            'vm.file.install',
                            vm['template']['name'],
                            f['name'],
                            files_root if f['dest'] == '.' else os.path.join(files_root, f['dest']),
                            progress_callback=progress_cb
                        ))

        if progress_cb:
            progress_cb(100, 'Initializing VM files')

    def create_device(self, vm, res, progress_cb=None):
        if progress_cb:
            progress_cb(0, 'Creating {0}'.format(res['type'].lower()))

        if 'id' in vm:
            reserved_datasets = self.dispatcher.call_sync('vm.get_reserved_datasets', vm['id'])
            if res['type'] in ['VOLUME', 'DISK']:
                new_ds = os.path.join(vm['target'], 'vm', vm['name'], res['name'])
                if new_ds in reserved_datasets:
                    ds_type = self.dispatcher.call_sync(
                        'zfs.dataset.query',
                        [('name', '=', new_ds)],
                        {'single': True, 'select': 'type'}
                    )
                    ds_type = 'VOLUME' if ds_type == 'FILESYSTEM' else 'DISK'
                    if not (ds_type == res['type'] == 'VOLUME'):
                        raise TaskException(
                            errno.EACCES,
                            'Cannot create device {1} {0}. One of VM snapshots is already using {2} {0}.'.format(
                                res['name'],
                                res['type'].lower(),
                                ds_type.lower()
                            )
                        )

        if res['type'] == 'GRAPHICS':
            if q.get(vm, 'config.bootloader') != 'UEFI':
                raise TaskException(errno.EINVAL, 'Graphical consoles are supported for UEFI bootloader only.')
            normalize(res['properties'], {'resolution': '1024x768'})

        if res['type'] == 'DISK':
            vm_ds = os.path.join(vm['target'], 'vm', vm['name'])
            ds_name = os.path.join(vm_ds, res['name'])
            self.join_subtasks(self.run_subtask('volume.dataset.create', {
                'volume': vm['target'],
                'id': ds_name,
                'type': 'VOLUME',
                'volsize': res['properties']['size']
            }))

            normalize(res['properties'], {
                'mode': 'AHCI'
            })

            if res['properties'].get('source'):
                self.join_subtasks(self.run_subtask(
                    'vm.file.install',
                    vm['template']['name'],
                    res['properties']['source'],
                    os.path.join('/dev/zvol', ds_name),
                    progress_callback=progress_cb
                ))

        if res['type'] == 'NIC':
            normalize(res['properties'], {
                'device': 'VIRTIO',
                'mode': 'NAT',
                'link_address': self.dispatcher.call_sync('vm.generate_mac')
            })

            brigde = res['properties'].get('bridge', 'default')
            if brigde != 'default':
                if_exists = self.dispatcher.call_sync(
                    'network.interface.query',
                    [('or', [('id', '=', brigde), ('name', '=', brigde)])],
                    {'single': True}
                )
                if not if_exists:
                    raise TaskException(
                        errno.ENOENT,
                        'Cannot create a bridge to {0}. Interface does not exist'.format(brigde)
                    )

        if res['type'] == 'VOLUME':
            properties = res['properties']
            mgmt_net = ipaddress.ip_interface(self.configstore.get('container.network.management'))
            vm_ds = os.path.join(vm['target'], 'vm', vm['name'])
            opts = {}

            normalize(res['properties'], {
                'type': 'VT9P',
                'auto': False
            })

            if properties['type'] == 'NFS':
                opts['sharenfs'] = {'value': '-network={0}'.format(str(mgmt_net.network))}
                if not self.configstore.get('service.nfs.enable'):
                    self.join_subtasks(self.run_subtask('service.update', 'nfs', {'enable': True}))

            if properties['type'] == 'VT9P':
                if properties.get('auto'):
                    ds_name = os.path.join(vm_ds, res['name'])
                    old_ds = self.dispatcher.call_sync('zfs.dataset.query', [('name', '=', ds_name)], {'single': True})
                    if not old_ds:
                        self.join_subtasks(self.run_subtask('volume.dataset.create', {
                            'volume': vm['target'],
                            'id': ds_name
                        }))

                    if properties.get('source'):
                        if old_ds:
                            shutil.rmtree(
                                self.dispatcher.call_sync('volume.get_dataset_path', ds_name),
                                ignore_errors=True
                            )

                        self.join_subtasks(self.run_subtask(
                            'vm.file.install',
                            vm['template']['name'],
                            properties['source'],
                            self.dispatcher.call_sync('volume.get_dataset_path', ds_name),
                            progress_callback=progress_cb
                        ))

        if progress_cb:
            progress_cb(100, 'Creating {0}'.format(res['type'].lower()))

    def update_device(self, vm, old_res, new_res):
        vm_ds = os.path.join(vm['target'], 'vm', vm['name'])
        if new_res['type'] in ['DISK', 'VOLUME']:
            if old_res['name'] != new_res['name']:
                if not (new_res['type'] == 'VOLUME' and not new_res['properties']['auto']):
                    self.join_subtasks(self.run_subtask(
                        'zfs.rename',
                        os.path.join(vm_ds, old_res['name']),
                        os.path.join(vm_ds, new_res['name'])
                    ))
                    if new_res['type'] == 'VOLUME':
                        self.join_subtasks(self.run_subtask('zfs.mount', os.path.join(vm_ds, new_res['name'])))
                        self.join_subtasks(self.run_subtask('zfs.umount', os.path.join(vm_ds, new_res['name'])))

        if new_res['type'] == 'DISK':
            if old_res['properties']['size'] != new_res['properties']['size']:
                ds_name = os.path.join(vm_ds, new_res['name'])
                self.join_subtasks(self.run_subtask(
                    'zfs.update',
                    ds_name,
                    {'volsize': {'value': new_res['properties']['size']}}
                ))

        if new_res['type'] == 'NIC':
            brigde = new_res['properties'].get('bridge', 'default')
            if brigde != 'default':
                if_exists = self.dispatcher.call_sync(
                    'network.interface.query',
                    [('or', [('id', '=', brigde), ('name', '=', brigde)])],
                    {'single': True}
                )
                if not if_exists:
                    raise TaskException(
                        errno.ENOENT,
                        'Cannot create a bridge to {0}. Interface does not exist'.format(brigde)
                    )

    def delete_device(self, vm, res):
        reserved_datasets = self.dispatcher.call_sync('vm.get_reserved_datasets', vm['id'])

        if res['type'] in ('DISK', 'VOLUME'):
            vm_ds = self.dispatcher.call_sync('vm.get_dataset', vm['id'])
            ds_name = os.path.join(vm_ds, res['name'])
            if ds_name in reserved_datasets:
                self.add_warning(TaskWarning(
                    errno.EACCES,
                    'Dataset {0} not deleted. There are VM snapshots related to this dataset'.format(ds_name)
                ))
            else:
                self.join_subtasks(self.run_subtask(
                    'volume.dataset.delete',
                    ds_name
                ))


@accepts(h.all_of(
    h.ref('vm'),
    h.required('name', 'target')
))
@description('Creates a VM')
class VMCreateTask(VMBaseTask):
    def __init__(self, dispatcher, datastore):
        super(VMCreateTask, self).__init__(dispatcher, datastore)
        self.id = None

    @classmethod
    def early_describe(cls):
        return 'Creating VM'

    def describe(self, vm):
        return TaskDescription('Creating VM {name}', name=vm.get('name', ''))

    def verify(self, vm):
        if not self.dispatcher.call_sync('volume.query', [('id', '=', vm['target'])], {'single': True}):
            raise VerifyException(errno.ENXIO, 'Volume {0} doesn\'t exist'.format(vm['target']))

        return ['zpool:{0}'.format(vm['target'])]

    def run(self, vm):
        def collect_download_progress(percentage, message=None, extra=None):
            split_message = message.split(' ')
            self.set_progress(
                percentage / 4,
                'Downloading VM files: {0} {1}'.format(split_message[-2], split_message[-1]),
                extra
            )

        def collect_progress(static_message, start_percentage, percentage, message=None, extra=None):
            self.set_progress(
                start_percentage + ((30 * (idx / devices_len)) + (0.3 * (percentage / devices_len))),
                '{0} {1}'.format(static_message, message),
                extra
            )

        self.set_progress(0, 'Creating VM')
        if vm.get('template'):
            template_name = vm['template'].get('name')
            template = None
            if template_name.startswith('ipfs://'):
                template = self.dispatcher.call_sync(
                    'vm.template.query',
                    [('template.hash', '=', template_name)],
                    {'single': True}
                )
                if not template:
                    self.set_progress(5, 'Fetching VM template from IPFS')
                    template_name = self.join_subtasks(self.run_subtask('vm.template.ipfs.fetch', template_name))[0]

            if not template:
                template = self.dispatcher.call_sync(
                    'vm.template.query',
                    [('template.name', '=', template_name)],
                    {'single': True}
                )

            if not template:
                raise TaskException(errno.ENOENT, 'Template {0} not found'.format(vm['template'].get('name')))

            vm['template']['name'] = template['template']['name']
            template['template'].pop('readme', None)

            result = {}
            for key in vm:
                if vm[key]:
                    result[key] = vm[key]
            deep_update(template, result)
            vm = template

            self.join_subtasks(self.run_subtask(
                'vm.cache.update',
                vm['template']['name'],
                progress_callback=collect_download_progress
            ))
        else:
            normalize(vm, {
                'config': {},
                'devices': []
            })

        normalize(vm, {
            'enabled': True,
            'immutable': False,
            'guest_type': 'other',
            'parent': None
        })

        normalize(vm['config'], {
            'memsize': 512,
            'ncpus': 1,
            'autostart': False,
            'logging': []
        })

        if vm['config']['ncpus'] > 16:
            raise TaskException(errno.EINVAL, 'Upper limit of VM cores exceeded. Maximum permissible value is 16.')

        self.set_progress(25, 'Initializing VM dataset')
        self.init_dataset(vm)
        devices_len = len(vm['devices'])
        for idx, res in enumerate(vm['devices']):
            res.pop('id', None)
            self.create_device(vm, res, lambda p, m, e=None: collect_progress('Initializing VM devices:', 30, p, m, e))

        self.init_files(vm, lambda p, m, e=None: self.chunk_progress(60, 90, 'Initializing VM files:', p, m, e))

        self.id = self.datastore.insert('vms', vm)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'create',
            'ids': [self.id]
        })

        vm = self.datastore.get_by_id('vms', self.id)
        self.set_progress(90, 'Saving VM configuration')
        save_config(
            self.dispatcher.call_sync(
                'volume.resolve_path',
                vm['target'],
                os.path.join('vm', vm['name'])
            ),
            'vm-{0}'.format(vm['name']),
            vm
        )
        self.set_progress(100, 'Finished')

        return self.id

    def rollback(self, vm):
        vm_ds = os.path.join(vm['target'], 'vm', vm['name'])

        if self.dispatcher.call_sync('volume.dataset.query', [('id', '=', vm_ds)], {'single': True}):
            self.join_subtasks(self.run_subtask('volume.dataset.delete', vm_ds))

        if self.id:
            with self.dispatcher.get_lock('vms'):
                self.dispatcher.run_hook('vm.pre_destroy', {'name': self.id})
                self.datastore.delete('vms', self.id)
                self.dispatcher.dispatch_event('vm.changed', {
                    'operation': 'delete',
                    'ids': [self.id]
                })


@accepts(str, str)
@returns(str)
@description('Imports existing VM')
class VMImportTask(VMBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Importing VM'

    def describe(self, name, volume):
        return TaskDescription('Importing VM {name}', name=name)

    def verify(self, name, volume):
        if not self.dispatcher.call_sync('volume.query', [('id', '=', volume)], {'single': True}):
            raise VerifyException(errno.ENXIO, 'Volume {0} doesn\'t exist'.format(volume))

        return ['zpool:{0}'.format(volume)]

    def run(self, name, volume):
        if self.datastore.exists('vms', ('name', '=', name)):
            raise TaskException(errno.EEXIST, 'VM {0} already exists'.format(name))

        try:
            vm = load_config(
                self.dispatcher.call_sync(
                    'volume.resolve_path',
                    volume,
                    os.path.join('vm', name)
                ),
                'vm-{0}'.format(name)
            )
        except FileNotFoundError:
            raise TaskException(errno.ENOENT, 'There is no {0} on {1} volume to be imported.'.format(name, volume))
        except ValueError:
            raise VerifyException(
                errno.EINVAL,
                'Cannot read configuration file. File is not a valid JSON file'
            )

        id = self.datastore.insert('vms', vm)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@private
@accepts(str, bool)
@description('Sets VM immutable')
class VMSetImmutableTask(VMBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating VM\'s immutable property'

    def describe(self, id, immutable):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription(
            'Setting {name} VM\'s immutable property to {value}',
            name=vm.get('name', '') if vm else '',
            value='on' if immutable else 'off'
        )

    def verify(self, id, immutable):
        return ['system']

    def run(self, id, immutable):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'VM {0} does not exist'.format(id))

        vm = self.datastore.get_by_id('vms', id)
        vm['enabled'] = not immutable
        vm['immutable'] = immutable
        self.datastore.update('vms', id, vm)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str, h.ref('vm'))
@description('Updates VM')
class VMUpdateTask(VMBaseTask):
    @classmethod
    def early_describe(cls):
        return 'Updating VM'

    def describe(self, id, updated_params):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Updating VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id, updated_params):
        if 'devices' in updated_params:
            name = ""
            graphics_exist = False
            for device in updated_params['devices']:
                if device['type'] == 'GRAPHICS':
                    if graphics_exist:
                        raise VerifyException(
                            errno.EEXIST,
                            'Multiple "GRAPHICS" type devices detected: {0},{1}'.format(
                                name,
                                device['name']
                            )
                        )
                    else:
                        graphics_exist = True
                        name = device['name']

        return ['system']

    def run(self, id, updated_params):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'VM {0} not found'.format(id))

        if 'config' in updated_params and updated_params['config']['ncpus'] > 16:
            raise TaskException(errno.EINVAL, 'Upper limit of VM cores exceeded. Maximum permissible value is 16.')

        vm = self.datastore.get_by_id('vms', id)
        if vm['immutable']:
            raise TaskException(errno.EACCES, 'Cannot modify immutable VM {0}.'.format(id))

        state = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'select': 'status.state', 'single': True})
        if state != 'STOPPED':
            if 'name' in updated_params:
                raise TaskException(errno.EACCES, 'Name of a running VM cannot be modified')

            runtime_static_params = (
                'guest_type', 'enabled', 'immutable', 'target', 'template', 'devices', 'config.memsize', 'config.ncpus',
                'config.bootloader', 'config.boot_device', 'config.boot_partition', 'config.boot_directory',
                'config.cloud_init', 'config.vnc_password'
            )

            if any(q.get(updated_params, key) and q.get(vm, key) != q.get(updated_params, key) for key in runtime_static_params):
                self.add_warning(TaskWarning(
                    errno.EACCES, 'Selected change set is going to take effect after VM {0} reboot'.format(vm['name'])
                ))

        try:
            delete_config(
                self.dispatcher.call_sync(
                    'volume.resolve_path',
                    vm['target'],
                    os.path.join('vm', vm['name'])
                ),
                'vm-{0}'.format(vm['name'])
            )
        except (RpcException, OSError):
            pass

        if 'name' in updated_params:
            root_ds = os.path.join(vm['target'], 'vm')
            vm_ds = os.path.join(root_ds, vm['name'])
            new_vm_ds = os.path.join(root_ds, updated_params['name'])

            self.join_subtasks(self.run_subtask('zfs.rename', vm_ds, new_vm_ds))

        old_vm = copy.deepcopy(vm)
        vm.update(updated_params)

        if 'config' in updated_params:
            readme = updated_params['config'].pop('readme', '')
            root = self.dispatcher.call_sync('vm.get_vm_root', vm['id'])
            readme_path = get_readme(root)
            if readme_path or readme:
                with open(os.path.join(root, 'README.md'), 'w') as readme_file:
                    readme_file.write(readme)

            if q.get(vm, 'config.bootloader') != 'UEFI':
                if first_or_default(lambda i: i['type'] == 'GRAPHICS', vm['devices']):
                    raise TaskException(
                        errno.EINVAL,
                        'Cannot change bootloader type. VM has graphical console - this is only supported in UEFI mode'
                    )

        if 'devices' in updated_params:
            for res in updated_params['devices']:
                res.pop('id', None)
                existing = first_or_default(lambda i: i['name'] == res['name'], old_vm['devices'])
                if existing:
                    self.update_device(vm, existing, res)
                else:
                    self.create_device(vm, res)

            for res in old_vm['devices']:
                if not first_or_default(lambda i: i['name'] == res['name'], updated_params['devices']):
                    self.delete_device(old_vm, res)

        if not updated_params.get('enabled', True):
            self.join_subtasks(self.run_subtask('vm.stop', id))

        self.datastore.update('vms', id, vm)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [id]
        })

        vm = self.datastore.get_by_id('vms', id)
        save_config(
            self.dispatcher.call_sync(
                'volume.resolve_path',
                vm['target'],
                os.path.join('vm', vm['name'])
            ),
            'vm-{0}'.format(vm['name']),
            vm
        )


@accepts(str)
@description('Deletes VM')
class VMDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting VM'

    def describe(self, id):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Deleting VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'VM {0} not found'.format(id))

        vm = self.datastore.get_by_id('vms', id)
        try:
            delete_config(
                self.dispatcher.call_sync(
                    'volume.resolve_path',
                    vm['target'],
                    os.path.join('vm', vm['name'])
                ),
                'vm-{0}'.format(vm['name'])
            )
        except (RpcException, OSError):
            pass

        subtasks = []
        for snapshot in self.dispatcher.call_sync('vm.snapshot.query', [('parent.id', '=', id)]):
            subtasks.append(self.run_subtask('vm.snapshot.delete', snapshot['id']))
        self.join_subtasks(*subtasks)

        vm_ds = self.dispatcher.call_sync('vm.get_dataset', id)

        try:
            self.join_subtasks(self.run_subtask('vm.stop', id, True))
        except RpcException:
            pass

        try:
            self.join_subtasks(self.run_subtask('volume.dataset.delete', vm_ds))
        except RpcException as err:
            if err.code != errno.ENOENT:
                raise err

        with self.dispatcher.get_lock('vms'):
            self.dispatcher.run_hook('vm.pre_destroy', {'name': id})
            self.datastore.delete('vms', id)
            self.dispatcher.dispatch_event('vm.changed', {
                'operation': 'delete',
                'ids': [id]
            })


@accepts(str)
@description('Exports VM from database')
class VMExportTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Exporting VM'

    def describe(self, id):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Exporting VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('vms', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'VM {0} not found'.format(id))

        self.datastore.delete('vms', id)
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@accepts(str)
@description('Starts VM')
class VMStartTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Starting VM'

    def describe(self, id):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Starting VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id):
        vm = self.datastore.get_by_id('vms', id)
        config = vm.get('config')
        if not config or not config.get('bootloader'):
            raise VerifyException(errno.ENXIO, 'Please specify a bootloader for this vm.')
        if config['bootloader'] == 'BHYVELOAD' and not config.get('boot_device'):
            raise VerifyException(
                errno.ENXIO,
                'BHYVELOAD bootloader requires that you specify a boot device on your vm'
            )
        return ['system']

    def run(self, id):
        vm = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'single': True})
        if not vm['enabled']:
            raise TaskException(errno.EACCES, "Cannot start disabled VM {0}".format(id))

        try:
            self.dispatcher.call_sync('containerd.management.start_vm', id)
        except RpcException as err:
            raise TaskException(err.code, err.message)

        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str, bool)
@description('Stops VM')
class VMStopTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Stopping VM'

    def describe(self, id, force=False):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Stopping VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id, force=False):
        return ['system']

    def run(self, id, force=False):
        try:
            self.dispatcher.call_sync('containerd.management.stop_vm', id, force, timeout=120)
        except RpcException as err:
            raise TaskException(err.code, err.message)

        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str, bool)
@description('Reboots VM')
class VMRebootTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Rebooting VM'

    def describe(self, id, force=False):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Rebooting VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id, force=False):
        return ['system']

    def run(self, id, force=False):
        try:
            self.join_subtasks(self.run_subtask('vm.stop', id, force))
            self.join_subtasks(self.run_subtask('vm.start', id))
        except RpcException as err:
            raise TaskException(err.code, err.message)


@accepts(str)
@description('Returns VM to previously saved state')
class VMSnapshotRollbackTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Rollback of VM'

    def describe(self, id):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        vm_name = None
        if snapshot:
            vm_name = self.dispatcher.call_sync(
                'vm.query',
                [('id', '=', snapshot['parent'])],
                {'single': True, 'select': 'name'}
            )
        return TaskDescription('Rollback of VM {name}', name=vm_name or '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        vm = self.datastore.get_by_id('vms', snapshot['parent']['id'])
        if not vm:
            raise TaskException(errno.ENOENT, 'Prent VM {0} does not exist'.format(snapshot['parent']['name']))

        snapshot_id = self.dispatcher.call_sync(
            'zfs.snapshot.query',
            [('properties.org\.freenas:vm_snapshot.rawvalue', '=', id)],
            {'single': True, 'select': 'id'}
        )

        self.join_subtasks(self.run_subtask('zfs.rollback', snapshot_id, True, True))

        self.datastore.update('vms', snapshot['parent']['id'], snapshot['parent'])
        self.dispatcher.dispatch_event('vm.changed', {
            'operation': 'update',
            'ids': [snapshot['parent']['id']]
        })


@accepts(str, str, str)
@description('Creates a snapshot of VM')
class VMSnapshotCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating snapshot of VM'

    def describe(self, id, name, descr):
        vm = self.datastore.get_by_id('vms', id)
        return TaskDescription('Creating snapshot of VM {name}', name=vm.get('name', '') if vm else '')

    def verify(self, id, name, descr):
        return ['system']

    def run(self, id, name, descr):
        vm = self.datastore.get_by_id('vms', id)
        if not vm:
            raise TaskException(errno.ENOENT, 'VM {0} does not exist'.format(id))
        if vm['parent']:
            raise TaskException(errno.EACCES, 'Cannot create a snapshot of another snapshot')

        state = self.dispatcher.call_sync('vm.query', [('id', '=', id)], {'select': 'status.state', 'single': True})
        if state != 'STOPPED':
            raise TaskException(errno.EACCES, 'Cannot create a snapshot of a running VM')

        if self.dispatcher.call_sync('vm.snapshot.query', [('name', '=', name), ('parent.id', '=', id)], {'single': True}):
            raise TaskException(errno.EEXIST, 'Snapshot {0} of VM {1} already exists'.format(name, vm['name']))

        snapshot = {
            'name': name,
            'description': descr,
            'parent': vm
        }

        snapshot_id = self.datastore.insert('vm.snapshots', snapshot)
        self.dispatcher.dispatch_event('vm.snapshot.changed', {
            'operation': 'create',
            'ids': [snapshot_id]
        })

        snapname = name
        base_snapname = name
        vm_ds = self.dispatcher.call_sync('vm.get_dataset', id)

        # Pick another name in case snapshot already exists
        for i in range(1, 99):
            if self.dispatcher.call_sync(
                'zfs.snapshot.query',
                [('name', '=', '{0}@{1}'.format(vm_ds, snapname))],
                {'count': True}
            ):
                snapname = '{0}-{1}'.format(base_snapname, i)
                continue

            break

        self.join_subtasks(self.run_subtask(
            'zfs.create_snapshot',
            vm_ds,
            name,
            True,
            {
                'org.freenas:replicable': {'value': 'no'},
                'org.freenas:lifetime': {'value': 'no'},
                'org.freenas:uuid': {'value': str(uuid.uuid4())},
                'org.freenas:vm_snapshot': {'value': str(snapshot_id)},
            }
        ))


@accepts(str, h.ref('vm-snapshot'))
@description('Updates a snapshot of VM')
class VMSnapshotUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updates snapshot of VM'

    def describe(self, id, updated_params):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        return TaskDescription('Updating VM snapshot {name}', name=snapshot.get('name') if snapshot else '')

    def verify(self, id, updated_params):
        return ['system']

    def run(self, id, updated_params):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        if 'name' in updated_params:
            snapshot['name'] = updated_params['name']
        if 'description' in updated_params:
            snapshot['description'] = updated_params['description']

        self.datastore.update('vm.snapshots', id, snapshot)
        self.dispatcher.dispatch_event('vm.snapshot.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
@description('Deletes a snapshot of VM')
class VMSnapshotDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting snapshot of VM'

    def describe(self, id):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        return TaskDescription('Deleting VM snapshot {name}', name=snapshot.get('name') if snapshot else '')

    def verify(self, id):
        return ['system']

    def run(self, id):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        snapshot_ids = self.dispatcher.call_sync(
            'zfs.snapshot.query',
            [('properties.org\.freenas:vm_snapshot.rawvalue', '=', id)],
            {'select': 'id'}
        )

        self.datastore.delete('vm.snapshots', id)
        self.dispatcher.dispatch_event('vm.snapshot.changed', {
            'operation': 'delete',
            'ids': [id]
        })

        for snapshot_id in snapshot_ids:
            path, name = snapshot_id.split('@')
            self.join_subtasks(self.run_subtask('zfs.delete_snapshot', path, name))

        vm_id = snapshot['parent']['id']
        related_datasets = self.dispatcher.call_sync('vm.get_dependent_datasets', vm_id)
        related_datasets.extend(self.dispatcher.call_sync('vm.get_reserved_datasets', vm_id))
        vm_dataset = self.dispatcher.call_sync('vm.get_dataset', vm_id)
        child_datasets = self.dispatcher.call_sync(
            'zfs.dataset.query',
            [('id', '~', '^({0}/)'.format(vm_dataset))],
            {'select': 'name'}
        )

        unrelated_datasets = [d for d in child_datasets if d not in related_datasets]
        for d in unrelated_datasets:
            self.join_subtasks(self.run_subtask('volume.dataset.delete', d))


@accepts(str, str, str, str, str)
@returns(str)
@description('Publishes VM snapshot over IPFS')
class VMSnapshotPublishTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Publishing VM snapshot'

    def describe(self, id, name, author, mail, descr):
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        return TaskDescription('Publishing VM snapshot {name}', name=snapshot.get('name', '') if snapshot else '')

    def verify(self, id, name, author, mail, descr):
        return ['system', 'system-dataset']

    def run(self, id, name, author, mail, descr):
        ipfs_state = self.dispatcher.call_sync(
            'service.query',
            [('name', '=', 'ipfs')],
            {'single': True, 'select': 'state'}
        )
        if ipfs_state == 'STOPPED':
            raise TaskException(errno.EIO, 'IPFS service is not running. You have to start it first.')

        if self.dispatcher.call_sync('vm.template.query', [('template.name', '=', name)], {'single': True}):
            raise TaskException(errno.EEXIST, 'Template {0} already exists'.format(name))

        self.set_progress(0, 'Preparing template file')
        snapshot = self.datastore.get_by_id('vm.snapshots', id)
        if not snapshot:
            raise TaskException(errno.ENOENT, 'Snapshot {0} does not exist'.format(id))

        vm = self.datastore.get_by_id('vms', snapshot['parent']['id'])
        if not vm:
            raise TaskException(errno.ENOENT, 'Prent VM {0} does not exist'.format(snapshot['parent']['name']))

        snapshot_id = self.dispatcher.call_sync(
            'zfs.snapshot.query',
            [('properties.org\.freenas:vm_snapshot.rawvalue', '=', id)],
            {'single': True, 'select': 'id'}
        )

        ds_name, snap_name = snapshot_id.split('@')
        publish_ds = os.path.join(ds_name, 'publish')
        cache_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')
        templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')

        parent = snapshot['parent']
        current_time = datetime.datetime.utcnow().isoformat().split('.')[0]
        template = {
            'template': {
                'name': name,
                'author': '{0} <{1}>'.format(author, mail),
                'description': descr,
                'created_at': {'$date': current_time},
                'updated_at': {'$date': current_time},
                'fetch': []
            },
            'config': parent['config'],
            'devices': parent['devices'],
            'type': 'VM'
        }

        self.set_progress(10, 'Preparing VM files')
        dev_cnt = len(template['devices'])

        for idx, d in enumerate(template['devices']):
            self.set_progress(10 + ((idx / dev_cnt) * 80), 'Preparing VM files: {0}'.format(d['name']))
            if (d['type'] == 'DISK') or (d['type'] == 'VOLUME' and d['properties'].get('auto')):
                source_name = d['name']
                d['properties']['source'] = source_name
                dev_snapshot = os.path.join(ds_name, source_name) + '@' + snap_name
                dest_path = os.path.join(cache_dir, name, d['name'])

                if not os.path.isdir(dest_path):
                    os.makedirs(dest_path)

                self.join_subtasks(self.run_subtask('zfs.clone', dev_snapshot, publish_ds))

                dest_file = None
                if d['type'] == 'DISK':
                    dest_file = os.path.join(dest_path, d['name'] + '.gz')

                    with open(os.path.join('/dev/zvol', publish_ds), 'rb') as zvol:
                        with gzip.open(dest_file, 'wb') as file:
                            for chunk in iter(lambda: zvol.read(BLOCKSIZE), b""):
                                file.write(chunk)

                elif d['type'] == 'VOLUME':
                    dest_file = os.path.join(dest_path, d['name'] + '.tar.gz')
                    self.join_subtasks(self.run_subtask('zfs.mount', publish_ds))
                    with tarfile.open(dest_file, 'w:gz') as tar_file:
                        tar_file.add(self.dispatcher.call_sync('volume.get_dataset_path', publish_ds))
                        tar_file.close()
                    self.join_subtasks(self.run_subtask('zfs.umount', publish_ds))

                if dest_file:
                    self.join_subtasks(self.run_subtask('zfs.destroy', publish_ds))

                    sha256_hash = sha256(dest_file, BLOCKSIZE)

                    ipfs_hashes = self.join_subtasks(self.run_subtask('ipfs.add', dest_path, True))[0]
                    ipfs_hash = self.get_path_hash(ipfs_hashes, dest_path)

                    with open(os.path.join(dest_path, 'sha256'), 'w') as f:
                        f.write(sha256_hash)

                    template['template']['fetch'].append(
                        {
                            'name': d['name'],
                            'url': self.dispatcher.call_sync('ipfs.hash_to_link', ipfs_hash),
                            'sha256': sha256_hash
                        }
                    )

        self.set_progress(90, 'Publishing template')
        template_path = os.path.join(templates_dir, 'ipfs', name)
        if not os.path.isdir(template_path):
            os.makedirs(template_path)

        self.join_subtasks(self.run_subtask('zfs.clone', snapshot_id, publish_ds))
        self.join_subtasks(self.run_subtask('zfs.mount', publish_ds))
        copytree(self.dispatcher.call_sync('volume.get_dataset_path', publish_ds), template_path)
        self.join_subtasks(self.run_subtask('zfs.umount', publish_ds))
        self.join_subtasks(self.run_subtask('zfs.destroy', publish_ds))

        try:
            os.remove(os.path.join(template_path, '.config-vm-{0}.json'.format(parent['name'])))
        except FileNotFoundError:
            pass

        with open(os.path.join(template_path, 'template.json'), 'w') as f:
            f.write(dumps(template))

        ipfs_hashes = self.join_subtasks(self.run_subtask('ipfs.add', template_path, True))[0]
        ipfs_link = 'ipfs://' + self.get_path_hash(ipfs_hashes, template_path)
        self.set_progress(100, 'Upload finished - template link: {0}'.format(ipfs_link))
        with open(os.path.join(template_path, 'hash'), 'w') as hash_file:
            hash_file.write(ipfs_link)

    def get_path_hash(self, ipfs_hashes, dest_path):
        for ipfs_hash in ipfs_hashes:
            if ipfs_hash['Name'] == dest_path and 'Hash' in ipfs_hash:
                return ipfs_hash['Hash']


@accepts(str)
@description('Caches VM files')
class CacheFilesTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Caching VM files'

    def describe(self, name):
        return TaskDescription('Caching VM files {name}', name=name or '')

    def verify(self, name):
        return ['system-dataset']

    def run(self, name):
        def collect_progress(percentage, message=None, extra=None):
            self.set_progress(
                (100 * (weight * idx)) + (percentage * weight),
                'Caching files: {0}'.format(message), extra
            )

        cache_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')
        template = self.dispatcher.call_sync(
            'vm.template.query',
            [('template.name', '=', name)],
            {'single': True}
        )
        if not template:
            raise TaskException(errno.ENOENT, 'Template of VM {0} does not exist'.format(name))

        self.set_progress(0, 'Caching images')
        res_cnt = len(template['template']['fetch'])
        weight = 1 / res_cnt

        for idx, res in enumerate(template['template']['fetch']):
            url = res['url']
            res_name = res['name']
            destination = os.path.join(cache_dir, name, res_name)
            sha256 = res['sha256']

            sha256_path = os.path.join(destination, 'sha256')
            if os.path.isdir(destination):
                if os.path.exists(sha256_path):
                    with open(sha256_path) as sha256_file:
                        if sha256_file.read() == sha256:
                            continue
            else:
                os.makedirs(destination)

            self.join_subtasks(self.run_subtask(
                'vm.file.download',
                url,
                sha256,
                destination,
                progress_callback=collect_progress
            ))

        self.set_progress(100, 'Cached images')


@accepts(str)
@description('Deletes cached VM files')
class DeleteFilesTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting cached VM files'

    def describe(self, name):
        return TaskDescription('Deleting cached VM {name} files', name=name)

    def verify(self, name):
        return ['system-dataset']

    def run(self, name):
        cache_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')
        images_dir = os.path.join(cache_dir, name)
        shutil.rmtree(images_dir)


@description('Deletes all of cached VM files')
class FlushFilesTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Deleting VM files cache'

    def describe(self):
        return TaskDescription('Deleting VM files cache')

    def verify(self):
        return ['system-dataset']

    def run(self):
        cache_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')
        shutil.rmtree(cache_dir)


@private
@accepts(str, str, str)
@description('Downloads VM file')
class DownloadFileTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading VM file'

    def describe(self, url, sha256_hash, destination):
        return TaskDescription('Downloading VM file {name}', name=url or '')

    def verify(self, url, sha256_hash, destination):
        return ['system-dataset']

    def run(self, url, sha256_hash, destination):
        done = 0

        @throttle(seconds=1)
        def progress_hook(nblocks, blocksize, totalsize):
            nonlocal done
            current_done = nblocks * blocksize
            speed = (current_done - done) / 1000
            self.set_progress((current_done / float(totalsize)) * 100, 'Downloading file {0} KB/s'.format(speed))
            done = current_done

        file_path = os.path.join(destination, url.split('/')[-1])
        sha256_path = os.path.join(destination, 'sha256')

        self.set_progress(0, 'Downloading file')
        try:
            if url.startswith('http://ipfs.io/ipfs/'):
                self.set_progress(50, 'Fetching file through IPFS')
                self.join_subtasks(self.run_subtask('ipfs.get', url.split('/')[-1], destination))
            else:
                try:
                    urllib.request.urlretrieve(url, file_path, progress_hook)
                except ConnectionResetError:
                    raise TaskException(errno.ECONNRESET, 'Cannot access download server to download {0}'.format(url))
        except OSError:
            raise TaskException(errno.EIO, 'URL {0} could not be downloaded'.format(url))

        if os.path.isdir(file_path):
            for f in os.listdir(file_path):
                shutil.move(os.path.join(file_path, f), destination)
            os.rmdir(file_path)
            file_path = os.path.join(destination, f)

        self.set_progress(100, 'Verifying checksum')
        if sha256(file_path, BLOCKSIZE) != sha256_hash:
            raise TaskException(errno.EINVAL, 'Invalid SHA256 checksum')

        with open(sha256_path, 'w') as sha256_file:
            sha256_file.write(sha256_hash)


@private
@accepts(str, str, str)
@description('Installs VM file')
class InstallFileTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Installing VM file'

    def describe(self, name, res, destination):
        return TaskDescription(
            'Installing VM file {name} in {destination}',
            name=os.path.join(name, res) or '',
            destination=destination or ''
        )

    def verify(self, name, res, destination):
        return ['system-dataset']

    def run(self, name, res, destination):
        self.set_progress(0, 'Installing file')
        cache_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')
        files_path = os.path.join(cache_dir, name, res)
        file_path = self.get_archive_path(files_path)

        if not file_path:
            raise TaskException(errno.ENOENT, 'File {0} not found'.format(files_path))

        if file_path.endswith('tar.gz'):
            shutil.unpack_archive(file_path, destination)
        else:
            if os.path.isdir(destination):
                destination = os.path.join(destination, res)
            self.unpack_gzip(file_path, destination)

        self.set_progress(100, 'Finished')

    def get_archive_path(self, files_path):
        archive_path = None
        for file in os.listdir(files_path):
            if file.endswith('.gz'):
                archive_path = os.path.join(files_path, file)
        return archive_path

    def unpack_gzip(self, path, destination):
        @throttle(seconds=1)
        def report_progress():
            self.set_progress((zip_file.tell() / size) * 100, 'Installing file')

        size = os.path.getsize(path)
        with open(destination, 'wb') as dst:
            with open(path, 'rb') as zip_file:
                with gzip.open(zip_file) as src:
                    for chunk in iter(lambda: src.read(BLOCKSIZE), b""):
                        done = 0
                        total = len(chunk)

                        while done < total:
                            ret = os.write(dst.fileno(), chunk[done:])
                            if ret == 0:
                                raise TaskException(errno.ENOSPC, 'Image is too large to fit in destination')

                            done += ret
                        report_progress()


@private
@description('Downloads VM templates')
class VMTemplateFetchTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading VM templates'

    def describe(self):
        return TaskDescription('Downloading VM templates')

    def verify(self):
        return ['system-dataset']

    def run(self):
        def clean_clone(url, path):
            try:
                shutil.rmtree(path)
            except shutil.Error:
                raise TaskException(errno.EACCES, 'Cannot remove templates directory: {0}'.format(path))
            except FileNotFoundError:
                pass
            try:
                pygit2.clone_repository(url, path)
            except pygit2.GitError:
                self.add_warning(TaskWarning(
                    errno.EACCES,
                    'Cannot update template cache. Result is outdated. Check networking.'))
                return

        templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')

        progress = 0
        self.set_progress(progress, 'Downloading templates')
        template_sources = self.datastore.query('vm.template_sources')
        template_sources.extend(self.dispatcher.call_sync('vm.config.get_config').get('additional_templates', []))

        if len(template_sources):
            progress_per_source = 100 / len(template_sources)
            for source in template_sources:
                if source.get('driver', '') == 'git':
                    source_path = os.path.join(templates_dir, source['id'])

                    if os.path.exists(os.path.join(source_path, '.git')):
                        try:
                            repo = pygit2.init_repository(source_path, False)

                            for remote in repo.remotes:
                                if remote.name == 'origin':
                                    remote.fetch()
                                    remote_master_id = repo.lookup_reference('refs/remotes/origin/master').target
                                    merge_result, _ = repo.merge_analysis(remote_master_id)

                                    if merge_result & pygit2.GIT_MERGE_ANALYSIS_UP_TO_DATE:
                                        continue
                                    elif merge_result & pygit2.GIT_MERGE_ANALYSIS_FASTFORWARD:
                                        repo.checkout_tree(repo.get(remote_master_id))
                                        master_ref = repo.lookup_reference('refs/heads/master')
                                        master_ref.set_target(remote_master_id)
                                        repo.head.set_target(remote_master_id)
                                    else:
                                        clean_clone(source['url'], source_path)
                        except (pygit2.GitError, KeyError):
                            self.add_warning(TaskWarning(
                                errno.EACCES,
                                'Cannot update template cache. Result is outdated. Check networking.'))
                            return
                    else:
                        clean_clone(source['url'], source_path)

                self.set_progress(progress + progress_per_source, 'Finished operation for {0}'.format(source['id']))

        self.set_progress(100, 'Templates downloaded')


@accepts(str)
@returns(str)
@description('Downloads VM template via IPFS')
class VMIPFSTemplateFetchTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Downloading VM template via IPFS'

    def describe(self, ipfs_hash):
        return TaskDescription('Downloading VM template via IPFS {name}', name=ipfs_hash)

    def verify(self, ipfs_hash):
        return ['system-dataset']

    def run(self, ipfs_hash):
        ipfs_state = self.dispatcher.call_sync(
            'service.query',
            [('name', '=', 'ipfs')],
            {'single': True, 'select': 'state'}
        )
        if ipfs_state == 'STOPPED':
            raise TaskException(errno.EIO, 'IPFS service is not running. You have to start it first.')

        templates_dir = self.dispatcher.call_sync('system_dataset.request_directory', 'vm_templates')
        ipfs_templates_dir = os.path.join(templates_dir, 'ipfs')
        if not os.path.isdir(ipfs_templates_dir):
            os.makedirs(ipfs_templates_dir)

        raw_hash = ipfs_hash.split('/')[-1]

        self.join_subtasks(self.run_subtask('ipfs.get', raw_hash, ipfs_templates_dir))

        new_template_dir = os.path.join(ipfs_templates_dir, raw_hash)
        try:
            with open(os.path.join(new_template_dir, 'template.json'), encoding='utf-8') as template_file:
                template = loads(template_file.read())
                with open(os.path.join(new_template_dir, 'hash'), 'w') as hash_file:
                    hash_file.write(ipfs_hash)
                template_name = template['template']['name']

        except OSError:
            shutil.rmtree(new_template_dir)
            raise TaskException(errno.EINVAL, '{0} is not a valid IPFS template'.format(ipfs_hash))

        shutil.move(new_template_dir, os.path.join(ipfs_templates_dir, template_name))
        return template_name


@accepts(str)
@description('Deletes VM template images and VM template itself')
class VMTemplateDeleteTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return 'Deleting VM template images and VM template'

    def describe(self, name):
        return TaskDescription('Deleting VM template images and VM template {name}', name=name)

    def verify(self, name):
        return ['system-dataset']

    def run(self, name):
        template = self.dispatcher.call_sync(
            'vm.template.query',
            [('template.name', '=', name)],
            {'single': True, 'select': 'template'}
        )
        if not template:
            raise TaskException(errno.ENOENT, 'Template {0} does not exist'.format(name))

        if template['source'] == 'github':
            raise TaskException(errno.EINVAL, 'Default templates cannot be deleted')

        template_path = template.get('path')
        if not template_path:
            raise TaskException(errno.ENOENT, 'Selected template {0} does not exist'.format(name))

        self.join_subtasks(self.run_subtask('vm.cache.delete', name))
        shutil.rmtree(template_path)


def get_readme(path):
    file_path = None
    for file in os.listdir(path):
        if file == 'README.md':
            file_path = os.path.join(path, file)

    return file_path


@throttle(minutes=10)
def fetch_templates(dispatcher):
    dispatcher.call_task_sync('vm.template.fetch')


def collect_debug(dispatcher):
    yield AttachDirectory('vm-templates', dispatcher.call_sync('system_dataset.request_directory', 'vm_templates'))
    yield AttachCommandOutput(
        'vm-images',
        ['ls', '-LRl', dispatcher.call_sync('system_dataset.request_directory', 'vm_image_cache')]
    )
    yield AttachData('vm-query', dumps(list(dispatcher.call_sync('vm.query')), indent=4))
    yield AttachData('vm-config', dumps(dispatcher.call_sync('vm.config.get_config'), indent=4))
    yield AttachData('vm-templates-query', dumps(list(dispatcher.call_sync('vm.template.query')), indent=4))
    yield AttachData('vm-snapshot-query', dumps(list(dispatcher.call_sync('vm.snapshot.query')), indent=4))
    yield AttachData('hw-support', dumps(dispatcher.call_sync('vm.get_hw_vm_capabilities'), indent=4))


def _depends():
    return ['VolumePlugin']


def _init(dispatcher, plugin):
    plugin.register_schema_definition('vm-status', {
        'type': 'object',
        'readOnly': True,
        'properties': {
            'state': {'$ref': 'vm-status-state'},
            'health': {'$ref': 'vm-status-health'},
            'vm_tools_available': {'type': 'boolean'},
            'nat_lease': {'oneOf': [
                {'$ref': 'vm-status-lease'},
                {'type': 'null'}
            ]},
            'management_lease': {'oneOf': [
                {'$ref': 'vm-status-lease'},
                {'type': 'null'}
            ]}
        }
    })

    plugin.register_schema_definition('vm-status-state', {
        'type': 'string',
        'enum': ['STOPPED', 'BOOTLOADER', 'RUNNING']
    })

    plugin.register_schema_definition('vm-status-health', {
        'type': 'string',
        'enum': ['HEALTHY', 'DYING', 'DEAD', 'UNKNOWN']
    })

    plugin.register_schema_definition('vm-status-lease', {
        'type': 'object',
        'properties': {
            'client_ip': {'type': 'string'},
        }
    })

    plugin.register_schema_definition('vm', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'guest_type': {'$ref': 'vm-guest-type'},
            'status': {'$ref': 'vm-status'},
            'description': {'type': 'string'},
            'enabled': {'type': 'boolean'},
            'immutable': {'type': 'boolean'},
            'target': {'type': 'string'},
            'template': {
                'type': ['object', 'null'],
                'properties': {
                    'name': {'type': 'string'},
                    'path': {'type': 'string'},
                    'source': {'type': 'string'},
                    'readme': {'type': ['string', 'null']},
                    'cached': {'type': 'boolean'}
                }
            },
            'config': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'memsize': {'type': 'integer'},
                    'ncpus': {'type': 'integer'},
                    'bootloader': {'$ref': 'vm-config-bootloader'},
                    'boot_device': {'type': ['string', 'null']},
                    'boot_partition': {'type': ['string', 'null']},
                    'boot_directory': {'type': ['string', 'null']},
                    'cloud_init': {'type': ['string', 'null']},
                    'vnc_password': {'type': ['string', 'null']},
                    'autostart': {'type': 'boolean'},
                    'docker_host': {'type': 'boolean'},
                    'readme': {'type': ['string', 'null']},
                    'logging': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    }
                }
            },
            'devices': {
                'type': 'array',
                'items': {'$ref': 'vm-device'}
            }
        }
    })

    plugin.register_schema_definition('vm-snapshot', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'description': {'type': 'string'},
            'parent': {'$ref': 'vm'}
        }
    })

    plugin.register_schema_definition('vm-config-bootloader', {
        'type': 'string',
        'enum': ['BHYVELOAD', 'GRUB', 'UEFI', 'UEFI_CSM']
    })

    plugin.register_schema_definition('vm-device', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'type': {'$ref': 'vm-device-type'},
            'properties': {
                'discriminator': '%type',
                'oneOf': [
                    {'$ref': 'vm-device-nic'},
                    {'$ref': 'vm-device-disk'},
                    {'$ref': 'vm-device-cdrom'},
                    {'$ref': 'vm-device-volume'},
                    {'$ref': 'vm-device-graphics'},
                    {'$ref': 'vm-device-usb'}
                ]
            }
        },
        'required': ['name', 'type', 'properties']
    })

    plugin.register_schema_definition('vm-device-type', {
        'type': 'string',
        'enum': ['DISK', 'CDROM', 'NIC', 'VOLUME', 'GRAPHICS', 'USB']
    })

    plugin.register_schema_definition('vm-device-nic', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-device-nic']},
            'device': {'$ref': 'vm-device-nic-device'},
            'mode': {'$ref': 'vm-device-nic-mode'},
            'link_address': {'type': 'string'},
            'bridge': {'type': ['string', 'null']}
        }
    })

    plugin.register_schema_definition('vm-device-nic-device', {
        'type': 'string',
        'enum': ['VIRTIO', 'E1000', 'NE2K']
    })

    plugin.register_schema_definition('vm-device-nic-mode', {
        'type': 'string',
        'enum': ['BRIDGED', 'NAT', 'HOSTONLY', 'MANAGEMENT']
    })

    plugin.register_schema_definition('vm-device-disk', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-device-disk']},
            'mode': {'$ref': 'vm-device-disk-mode'},
            'size': {'type': 'integer'},
            'source': {'type': 'string'}
        },
        'required': ['size']
    })

    plugin.register_schema_definition('vm-device-disk-mode', {
        'type': 'string',
        'enum': ['AHCI', 'VIRTIO']
    })

    plugin.register_schema_definition('vm-device-cdrom', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-device-cdrom']},
            'path': {'type': 'string'}
        },
        'required': ['path']

    })

    plugin.register_schema_definition('vm-device-volume', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-device-volume']},
            'type': {'$ref': 'vm-device-volume-type'},
            'auto': {'type': ['boolean', 'null']},
            'destination': {'type': ['string', 'null']},
            'source': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('vm-device-volume-type', {
        'type': 'string',
        'enum': ['VT9P', 'NFS']
    })

    plugin.register_schema_definition('vm-device-graphics', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-device-graphics']},
            'resolution': {'$ref': 'vm-device-graphics-resolution'},
            'vnc_enabled': {'type': 'boolean'},
            'vnc_port': {
                'type': ['integer', 'null'],
                'minimum': 1,
                'maximum': 65535
            }
        }
    })

    plugin.register_schema_definition('vm-device-graphics-resolution', {
        'type': 'string',
        'enum': [
            '1920x1200',
            '1920x1080',
            '1600x1200',
            '1600x900',
            '1280x1024',
            '1280x720',
            '1024x768',
            '800x600',
            '640x480'
        ]
    })

    plugin.register_schema_definition('vm-guest-type', {
        'type': 'string',
        'enum': [
            'linux64',
            'freebsd32',
            'freebsd64',
            'netbsd64',
            'openbsd32',
            'openbsd64',
            'windows64',
            'solaris64',
            'other'
        ]
    })

    plugin.register_schema_definition('vm-device-usb', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['vm-device-usb']},
            'device': {'$ref': 'vm-device-usb-device'},
            'config': {
                'type': 'object'  # XXX: not sure what goes there
            }
        },
        'required': ['device']
    })

    plugin.register_schema_definition('vm-device-usb-device', {
        'type': 'string',
        'enum': ['tablet']
    })

    plugin.register_schema_definition('vm-config', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'network': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'management': {'type': 'string'},
                    'nat': {'type': 'string'}
                }
            },
            'additional_templates': {
                'type': 'array',
                'items': {'$ref': 'vm-template-source'}
            }
        }
    })

    plugin.register_schema_definition('vm-template-source', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'driver': {'type': 'string'},
            'url': {'type': 'string'}
        }
    })

    plugin.register_schema_definition('vm-guest-info', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'vm_tools_version': {'type': 'string'},
            'load_avg': {
                'type': 'array',
                'items': {'type': 'number'},
                'minItems': 3,
                'maxItems': 4
            },
            'interfaces': {'type': 'object'},
            'time': {'type': 'datetime'}
        }
    })

    plugin.register_schema_definition('vm-hw-capabilites', {
        'type': 'object',
        'properties': {
            'vtx_enabled': {'type': 'boolean'},
            'svm_features': {'type': 'boolean'},
            'unrestricted_guest': {'type': 'boolean'}
        },
        'additionalProperties': False,
    })

    def volume_pre_detach(args):
        for vm in dispatcher.call_sync('vm.query'):
            if vm['target'] == args['name']:
                dispatcher.call_task_sync('vm.stop', vm['id'])
        return True

    def volume_pre_destroy(args):
        for vm in dispatcher.call_sync('vm.query'):
            if vm['target'] == args['name']:
                dispatcher.call_task_sync('vm.delete', vm['id'])
        return True

    def on_snapshot_change(args):
        if args['operation'] == 'delete':
            snaps = []
            for id in args['ids']:
                dataset, snapname = id.split('@', 1)
                if 'vm' not in dataset:
                    continue
                snaps.append(snapname)

            if snaps:
                vm_snapshots = dispatcher.call_sync('vm.snapshot.query', [('name', 'in', snaps)])
                with dispatcher.get_lock('vm_snapshots'):
                    logger.debug('ZFS snapshots deleted. Cleaning VM snapshots {0}'.format(snaps))
                    for i in vm_snapshots:
                        datasets = dispatcher.call_sync('vm.snapshot.get_dependent_datasets', i['id'])
                        for d in datasets:
                            ds_snapshot = dispatcher.call_sync(
                                'zfs.snapshot.query',
                                [
                                    ('id', '~', '^({0}@)'.format(d)),
                                    ('properties.org\.freenas:vm_snapshot.rawvalue', '=', i['id'])
                                ]
                            )
                            if not ds_snapshot:
                                dispatcher.call_task_sync('vm.snapshot.delete', i['id'])
                                logger.debug('Removed {0} VM snapshot'.format(i['name']))
                                break

    plugin.register_provider('vm', VMProvider)
    plugin.register_provider('vm.config', VMConfigProvider)
    plugin.register_provider('vm.snapshot', VMSnapshotProvider)
    plugin.register_provider('vm.template', VMTemplateProvider)
    plugin.register_task_handler('vm.create', VMCreateTask)
    plugin.register_task_handler('vm.import', VMImportTask)
    plugin.register_task_handler('vm.update', VMUpdateTask)
    plugin.register_task_handler('vm.delete', VMDeleteTask)
    plugin.register_task_handler('vm.export', VMExportTask)
    plugin.register_task_handler('vm.start', VMStartTask)
    plugin.register_task_handler('vm.stop', VMStopTask)
    plugin.register_task_handler('vm.reboot', VMRebootTask)
    plugin.register_task_handler('vm.snapshot.create', VMSnapshotCreateTask)
    plugin.register_task_handler('vm.snapshot.update', VMSnapshotUpdateTask)
    plugin.register_task_handler('vm.snapshot.delete', VMSnapshotDeleteTask)
    plugin.register_task_handler('vm.snapshot.rollback', VMSnapshotRollbackTask)
    plugin.register_task_handler('vm.snapshot.publish', VMSnapshotPublishTask)
    plugin.register_task_handler('vm.immutable.set', VMSetImmutableTask)
    plugin.register_task_handler('vm.file.install', InstallFileTask)
    plugin.register_task_handler('vm.file.download', DownloadFileTask)
    plugin.register_task_handler('vm.cache.update', CacheFilesTask)
    plugin.register_task_handler('vm.cache.delete', DeleteFilesTask)
    plugin.register_task_handler('vm.cache.flush', FlushFilesTask)
    plugin.register_task_handler('vm.template.fetch', VMTemplateFetchTask)
    plugin.register_task_handler('vm.template.delete', VMTemplateDeleteTask)
    plugin.register_task_handler('vm.template.ipfs.fetch', VMIPFSTemplateFetchTask)
    plugin.register_task_handler('vm.config.update', VMConfigUpdateTask)

    plugin.register_hook('vm.pre_destroy')

    plugin.attach_hook('volume.pre_destroy', volume_pre_destroy)
    plugin.attach_hook('volume.pre_detach', volume_pre_detach)

    plugin.register_event_type('vm.changed')
    plugin.register_event_type('vm.snapshot.changed')

    plugin.register_event_handler('zfs.snapshot.changed', on_snapshot_change)

    plugin.register_debug_hook(collect_debug)
