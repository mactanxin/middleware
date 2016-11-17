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

import errno
import ipaddress
import logging
import os
from freenas.dispatcher.rpc import RpcException, description, accepts, returns, generator
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.utils import normalize, query as q
from datastore.config import ConfigNode
from gevent import hub
from task import Provider, Task, TaskException, TaskDescription, query, TaskWarning
from debug import AttachFile, AttachCommandOutput


logger = logging.getLogger('NetworkPlugin')


def calculate_broadcast(address, netmask):
    return ipaddress.ip_interface('{0}/{1}'.format(address, netmask)).network.broadcast_address


@description("Provides access to global network configuration settings")
class NetworkProvider(Provider):
    @returns(h.ref('network-config'))
    def get_config(self):
        node = ConfigNode('network', self.configstore).__getstate__()
        node.update({
            'gateway': self.dispatcher.call_sync('networkd.configuration.get_default_routes'),
            'dns': self.dispatcher.call_sync('networkd.configuration.get_dns_config')
        })

        return node

    @returns(h.array(str))
    def get_my_ips(self):
        ips = []
        ifaces = self.dispatcher.call_sync('networkd.configuration.query_interfaces')
        ifaces.pop('mgmt0', None)
        for i, v in ifaces.items():
            if 'LOOPBACK' in v['flags'] or v['link_state'] != 'LINK_STATE_UP' or'UP' not in v['flags']:
                continue

            for aliases in v['aliases']:
                if aliases['address'] and aliases['type'] != 'LINK':
                    ips.append(aliases['address'])

        return list(set(ips))


@description("Provides access to network interface settings")
class InterfaceProvider(Provider):
    @query('network-interface')
    @generator
    def query(self, filter=None, params=None):
        ifaces = self.dispatcher.call_sync('networkd.configuration.query_interfaces')

        def extend(i):
            try:
                i['status'] = ifaces[i['id']]
            except KeyError:
                # The given interface is either removed or disconnected
                return None
            return i

        return q.query(
            self.datastore.query('network.interfaces', callback=extend),
            *(filter or []),
            stream=True,
            **(params or {})
        )


@description("Provides information on system's network routes")
class RouteProvider(Provider):
    @query('network-route')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('network.routes', *(filter or []), **(params or {}))


@description("Provides access to static host entries database")
class HostsProvider(Provider):
    @query('network-host')
    @generator
    def query(self, filter=None, params=None):
        return self.datastore.query_stream('network.hosts', *(filter or []), **(params or {}))


@description("Updates global network configuration settings")
@accepts(h.ref('network-config'))
class NetworkConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating global network settings"

    def describe(self, settings):
        return TaskDescription("Updating global network settings")

    def verify(self, settings):
        return ['system']

    def run(self, settings):
        node = ConfigNode('network', self.configstore)
        node.update(settings)
        dhcp_used = self.datastore.exists('network.interfaces', ('dhcp', '=', True))

        if dhcp_used:
            if node['dhcp.assign_gateway']:
                # Clear out gateway settings
                node['gateway.ipv4'] = None

            if node['dhcp.assign_dns']:
                # Clear out DNS settings
                node['dns.addresses'] = []
                node['dns.search'] = []

        try:
            for code, message in self.dispatcher.call_sync('networkd.configuration.configure_network', timeout=60):
                self.add_warning(TaskWarning(code, message))

            self.dispatcher.call_sync('etcd.generation.generate_group', 'network')
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure interface: {0}'.format(str(e)))


@accepts(h.all_of(
    h.ref('network-interface'),
    h.required('type'),
    h.forbidden('id', 'status')
))
@returns(str)
@description('Creates network interface')
class CreateInterfaceTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating network interface"

    def describe(self, iface):
        return TaskDescription("Creating {name} network interface", name=iface['type'])

    def verify(self, iface):
        return ['system']

    def run(self, iface):
        type = iface['type']
        name = self.dispatcher.call_sync('networkd.configuration.get_next_name', type)
        normalize(iface, {
            'id': name,
            'name': None,
            'type': type,
            'cloned': True,
            'enabled': True,
            'dhcp': False,
            'rtadv': False,
            'noipv6': False,
            'mtu': None,
            'media': None,
            'mediaopts': [],
            'aliases': [],
            'capabilities': {
                'add': [],
                'del': []
            }
        })

        if type == 'VLAN':
            iface.setdefault('vlan', {})
            normalize(iface['vlan'], {
                'parent': None,
                'tag': None
            })

        if type == 'LAGG':
            iface.setdefault('lagg', {})
            normalize(iface['lagg'], {
                'protocol': 'FAILOVER',
                'ports': []
            })

        if type == 'BRIDGE':
            iface.setdefault('bridge', {})
            normalize(iface['bridge'], {
                'members': []
            })

        if iface['mtu'] and iface['type'] == 'LAGG':
            raise TaskException(
                errno.EINVAL,
                'MTU cannot be configured for lagg interfaces - MTU of first member port is used'
            )

        if iface['dhcp']:
            # Check for DHCP inconsistencies
            # 1. Check whether DHCP is enabled on other interfaces
            # 2. Check whether DHCP configures default route and/or DNS server addresses
            dhcp_used = self.datastore.exists('network.interfaces', ('dhcp', '=', True), ('id', '!=', iface['id']))
            dhcp_gateway = self.configstore.get('network.dhcp.assign_gateway')
            dhcp_dns = self.configstore.get('network.dhcp.assign_dns')

            if dhcp_used and (dhcp_gateway or dhcp_dns):
                raise TaskException(
                    errno.ENXIO,
                    'DHCP gateway or DNS assignment is already enabled on another interface'
                )

            if dhcp_gateway:
                self.configstore.set('network.gateway.ipv4', None)

            if dhcp_dns:
                self.configstore.set('network.dns.search', [])
                self.configstore.set('network.dns.addresses', [])

        if iface['aliases']:
            # Forbid setting any aliases on interface with DHCP
            if iface['dhcp'] and len(iface['aliases']) > 0:
                raise TaskException(errno.EINVAL, 'Cannot set aliases when using DHCP')

            # Check for aliases inconsistencies
            ips = [x['address'] for x in iface['aliases']]
            if any(ips.count(x) > 1 for x in ips):
                raise TaskException(errno.ENXIO, 'Duplicated IP alias')

            # Add missing broadcast addresses and address family
            for i in iface['aliases']:
                normalize(i, {
                    'type': 'INET'
                })

                if not i.get('broadcast') and i['type'] == 'INET':
                    i['broadcast'] = str(calculate_broadcast(i['address'], i['netmask']))

        if iface.get('vlan'):
            vlan = iface['vlan']
            if (not vlan['parent'] and vlan['tag']) or (vlan['parent'] and not vlan['tag']):
                raise TaskException(errno.EINVAL, 'Can only set VLAN parent interface and tag at the same time')

        if iface.get('lagg'):
            lagg = iface['lagg']
            for i in lagg['ports']:
                member = self.datastore.get_by_id('network.interfaces', i)
                if not member:
                    raise TaskException(errno.EINVAL, 'Lagg member interface {0} doesn\'t exist'.format(i))

                if member['type'] in ('LAGG', 'VLAN'):
                    raise TaskException(errno.EINVAL, 'VLAN and LAGG interfaces cannot be members of a LAGG')

        self.datastore.insert('network.interfaces', iface)

        try:
            for code, message in self.dispatcher.call_sync('networkd.configuration.configure_network', timeout=60):
                self.add_warning(TaskWarning(code, message))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure network: {0}'.format(str(e)))

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'create',
            'ids': [name]
        })

        return name


@description("Deletes interface")
@accepts(str)
class DeleteInterfaceTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting network interface"

    def describe(self, id):
        return TaskDescription("Deleting network interface {name}", name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        iface = self.datastore.get_by_id('network.interfaces', id)
        if not iface:
            raise TaskException(errno.ENOENT, 'Interface {0} does not exist'.format(id))

        if iface['type'] not in ('VLAN', 'LAGG', 'BRIDGE'):
            raise TaskException(errno.EBUSY, 'Cannot delete physical interface')

        self.datastore.delete('network.interfaces', id)
        try:
            for code, message in self.dispatcher.call_sync('networkd.configuration.configure_network', timeout=60):
                self.add_warning(TaskWarning(code, message))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure network: {0}'.format(str(e)))

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@description("Alters network interface configuration")
@accepts(str, h.all_of(
    h.ref('network-interface'),
    h.forbidden('id', 'type', 'status')
))
class ConfigureInterfaceTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating configuration of network interface"

    def describe(self, id, updated_fields):
        return TaskDescription("Updating configuration of network interface {name}", name=id)

    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        if not self.datastore.exists('network.interfaces', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Interface {0} does not exist'.format(id))

        entity = self.datastore.get_by_id('network.interfaces', id)

        if updated_fields.get('mtu') and entity['type'] == 'LAGG':
            raise TaskException(
                errno.EINVAL,
                'MTU cannot be configured for lagg interfaces - MTU of first member port is used'
            )

        if updated_fields.get('dhcp'):
            # Check for DHCP inconsistencies
            # 1. Check whether DHCP is enabled on other interfaces
            # 2. Check whether DHCP configures default route and/or DNS server addresses
            dhcp_used = self.datastore.exists('network.interfaces', ('dhcp', '=', True), ('id', '!=', id))
            dhcp_gateway = self.configstore.get('network.dhcp.assign_gateway')
            dhcp_dns = self.configstore.get('network.dhcp.assign_dns')

            if dhcp_used and (dhcp_gateway or dhcp_dns):
                raise TaskException(
                    errno.ENXIO,
                    'DHCP gateway or DNS assignment is already enabled on another interface'
                )

            if dhcp_gateway:
                self.configstore.set('network.gateway.ipv4', None)

            if dhcp_dns:
                self.configstore.set('network.dns.search', [])
                self.configstore.set('network.dns.addresses', [])

            # Clear all aliases
            entity['aliases'] = []

        if updated_fields.get('aliases'):
            # Forbid setting any aliases on interface with DHCP
            if (updated_fields.get('dhcp') or entity['dhcp']) and updated_fields.get('dhcp') is not False and len(updated_fields['aliases']) > 0:
                raise TaskException(errno.EINVAL, 'Cannot set aliases when using DHCP')

            # Check for aliases inconsistencies
            ips = [x['address'] for x in updated_fields['aliases']]
            if any(ips.count(x) > 1 for x in ips):
                raise TaskException(errno.ENXIO, 'Duplicated IP alias')

            # Add missing broadcast addresses and address family
            for i in updated_fields['aliases']:
                normalize(i, {
                    'type': 'INET'
                })

                if not i.get('broadcast') and i['type'] == 'INET':
                    i['broadcast'] = str(calculate_broadcast(i['address'], i['netmask']))

        if updated_fields.get('vlan'):
            vlan = updated_fields['vlan']
            if (not vlan['parent'] and vlan['tag']) or (vlan['parent'] and not vlan['tag']):
                raise TaskException(errno.EINVAL, 'Can only set VLAN parent interface and tag at the same time')

        if updated_fields.get('lagg'):
            lagg = updated_fields['lagg']
            for i in lagg['ports']:
                member = self.datastore.get_by_id('network.interfaces', i)
                if not member:
                    raise TaskException(errno.EINVAL, 'Lagg member interface {0} doesn\'t exist'.format(i))

                if member['type'] in ('LAGG', 'VLAN'):
                    raise TaskException(errno.EINVAL, 'VLAN and LAGG interfaces cannot be members of a LAGG')

        entity.update(updated_fields)
        self.datastore.update('network.interfaces', id, entity)

        try:
            for code, message in self.dispatcher.call_sync('networkd.configuration.configure_network'):
                self.add_warning(TaskWarning(code, message))
        except RpcException as err:
            raise TaskException(err.code, 'Cannot reconfigure interface: {0}'.format(err.message))

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'update',
            'ids': [id]
        })


@description("Enables interface")
@accepts(str)
class InterfaceUpTask(Task):
    @classmethod
    def early_describe(cls):
        return "Setting network interface up"

    def describe(self, id):
        return TaskDescription("Setting network interface {name} up", name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        iface = self.datastore.get_by_id('network.interfaces', id)
        if not iface:
            raise TaskException(errno.ENOENT, 'Interface {0} does not exist'.format(id))

        if not iface['enabled']:
            raise TaskException(errno.ENXIO, 'Interface {0} is disabled'.format(id))

        try:
            for code, message in self.dispatcher.call_sync('networkd.configuration.up_interface', id):
                self.add_warning(TaskWarning(code, message))
        except RpcException as err:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure interface: {0}'.format(str(err)))

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'update',
            'ids': [id]
        })


@description("Disables interface")
@accepts(str)
class InterfaceDownTask(Task):
    @classmethod
    def early_describe(cls):
        return "Setting network interface down"

    def describe(self, id):
        return TaskDescription("Setting network interface {name} down", name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        iface = self.datastore.get_by_id('network.interfaces', id)
        if not iface:
            raise TaskException(errno.ENOENT, 'Interface {0} does not exist'.format(id))

        if not iface['enabled']:
            raise TaskException(errno.ENXIO, 'Interface {0} is disabled'.format(id))

        try:
            self.dispatcher.call_sync('networkd.configuration.down_interface', id)
        except RpcException as err:
            raise TaskException(err.code, err.message, err.extra)

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'update',
            'ids': [id]
        })


@description("Renews IP lease on interface")
@accepts(str)
class InterfaceRenewTask(Task):
    @classmethod
    def early_describe(cls):
        return "Renewing IP address of network interface"

    def describe(self, id):
        iface = self.datastore.get_by_id('network.interfaces', id)
        return TaskDescription("Renewing IP address of network interface {name}", name=iface.get('name', ''))

    def verify(self, id):
        return ['system']

    def run(self, id):
        interface = self.datastore.get_by_id('network.interfaces', id)
        if not interface:
            raise TaskException(errno.ENOENT, 'Interface {0} does not exist'.format(id))

        if not interface['enabled']:
            raise TaskException(errno.ENXIO, 'Interface {0} is disabled'.format(id))

        if not interface['dhcp']:
            raise TaskException(errno.EINVAL, 'Cannot renew a lease on interface that is not configured for DHCP')

        try:
            self.dispatcher.call_sync('networkd.configuration.renew_lease', id)
        except RpcException as err:
            raise TaskException(err.code, err.message, err.extra)

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'update',
            'ids': [id]
        })


@description("Adds host entry to the database")
@accepts(h.all_of(
    h.ref('network-host'),
    h.required('id', 'addresses')
))
class AddHostTask(Task):
    @classmethod
    def early_describe(cls):
        return "Adding static host"

    def describe(self, host):
        return TaskDescription("Adding static host {name}", name=host['id'])

    def verify(self, host):
        return ['system']

    def run(self, host):
        if self.datastore.exists('network.hosts', ('id', '=', host['id'])):
            raise TaskException(errno.EEXIST, 'Host entry {0} already exists'.format(host['id']))

        self.datastore.insert('network.hosts', host)
        self.dispatcher.dispatch_event('network.host.changed', {
            'operation': 'create',
            'ids': [host['id']]
        })


@description("Updates host entry in the database")
@accepts(str, h.ref('network-host'))
class UpdateHostTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating static host"

    def describe(self, id, updated_fields):
        return TaskDescription("Updating static host {name}", name=id)

    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        if not self.datastore.exists('network.hosts', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Host entry {0} does not exist'.format(id))

        host = self.datastore.get_one('network.hosts', ('id', '=', id))
        host.update(updated_fields)
        self.datastore.update('network.hosts', host['id'], host)
        self.dispatcher.dispatch_event('network.host.changed', {
            'operation': 'update',
            'ids': [id]
        })


@description("Deletes host entry from the database")
@accepts(str)
class DeleteHostTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting static host"

    def describe(self, id):
        return TaskDescription("Deleting static host {name}", name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('network.hosts', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Host entry {0} does not exist'.format(id))

        self.datastore.delete('network.hosts', id)
        self.dispatcher.dispatch_event('network.host.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@description("Adds static route to the system")
@accepts(h.all_of(
    h.ref('network-route'),
    h.required('id', 'type', 'network', 'netmask', 'gateway')
))
class AddRouteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Adding static route"

    def describe(self, route):
        return TaskDescription("Adding static route {name}", name=route['id'])

    def verify(self, route):
        return ['system']

    def run(self, route):
        if self.datastore.exists('network.routes', ('id', '=', route['id'])):
            raise TaskException(errno.EEXIST, 'Route {0} exists'.format(route['id']))

        for r in self.dispatcher.call_sync('network.route.query'):
            if (r['network'] == route['network']) and \
               (r['netmask'] == route['netmask']) and \
               (r['gateway'] == route['gateway']):
                raise TaskException(errno.EINVAL, 'Cannot create two identical routes differing only in name.')

        if route['type'] == 'INET':
            max_cidr = 32
        else:
            max_cidr = 128
        if not (0 <= route['netmask'] <= max_cidr):
            raise TaskException(
                errno.EINVAL,
                'Netmask value {0} is not valid. Allowed values are 0-{1} (CIDR).'.format(route['netmask'], max_cidr)
            )

        try:
            ipaddress.ip_network(os.path.join(route['network'], str(route['netmask'])))
        except ValueError:
            raise TaskException(
                errno.EINVAL,
                '{0} would have host bits set. Change network or netmask to represent a valid network'.format(
                    os.path.join(route['network'], str(route['netmask']))
                )
            )

        network = ipaddress.ip_network(os.path.join(route['network'], str(route['netmask'])))
        if ipaddress.ip_address(route['gateway']) in network:
            self.add_warning(
                TaskWarning(
                    errno.EINVAL,
                    'Gateway {0} is in the destination network {1}.'.format(route['gateway'], network.exploded)
                )
            )

        self.datastore.insert('network.routes', route)
        try:
            for code, message in self.dispatcher.call_sync('networkd.configuration.configure_routes'):
                self.add_warning(TaskWarning(code, message))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure routes: {0}'.format(str(e)))

        self.dispatcher.dispatch_event('network.route.changed', {
            'operation': 'create',
            'ids': [route['id']]
        })


@description("Updates static route in the system")
@accepts(str, h.ref('network-route'))
class UpdateRouteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating static route"

    def describe(self, name, updated_fields):
        return TaskDescription("Updating static route {name}", name=name)

    def verify(self, name, updated_fields):
        return ['system']

    def run(self, name, updated_fields):
        if not self.datastore.exists('network.routes', ('id', '=', name)):
            raise TaskException(errno.ENOENT, 'Route {0} does not exist'.format(name))

        route = self.datastore.get_one('network.routes', ('id', '=', name))
        net = updated_fields['network'] if 'network' in updated_fields else route['network']
        netmask = updated_fields['netmask'] if 'netmask' in updated_fields else route['netmask']
        type = updated_fields['type'] if 'type' in updated_fields else route['type']
        gateway = updated_fields['gateway'] if 'gateway' in updated_fields else route['gateway']

        if type == 'INET':
            max_cidr = 32
        else:
            max_cidr = 128
        if not (0 <= netmask <= max_cidr):
            raise TaskException(
                errno.EINVAL,
                'Netmask value {0} is not valid. Allowed values are 0-{1} (CIDR).'.format(route['netmask'], max_cidr)
            )

        try:
            ipaddress.ip_network(os.path.join(net, str(netmask)))
        except ValueError:
            raise TaskException(
                errno.EINVAL,
                '{0} would have host bits set. Change network or netmask to represent a valid network'.format(
                    os.path.join(net, str(netmask))
                )
            )

        network = ipaddress.ip_network(os.path.join(net, str(netmask)))
        if ipaddress.ip_address(gateway) in network:
            self.add_warning(
                TaskWarning(
                    errno.EINVAL,
                    'Gateway {0} is in the destination network {1}.'.format(gateway, network.exploded)
                )
            )

        route = self.datastore.get_one('network.routes', ('id', '=', name))
        route.update(updated_fields)
        self.datastore.update('network.routes', name, route)
        try:
            for code, message in self.dispatcher.call_sync('networkd.configuration.configure_routes'):
                self.add_warning(TaskWarning(code, message))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure routes: {0}'.format(str(e)))

        self.dispatcher.dispatch_event('network.route.changed', {
            'operation': 'update',
            'ids': [route['id']]
        })


@description("Deletes static route from the system")
@accepts(str)
class DeleteRouteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting static route"

    def describe(self, id):
        return TaskDescription("Deleting static route {name}", name=id)

    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('network.routes', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'route {0} does not exist'.format(id))

        self.datastore.delete('network.routes', id)
        try:
            for code, message in self.dispatcher.call_sync('networkd.configuration.configure_routes'):
                self.add_warning(TaskWarning(code, message))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure routes: {0}'.format(str(e)))

        self.dispatcher.dispatch_event('network.route.changed', {
            'operation': 'delete',
            'ids': [id]
        })


def collect_debug(dispatcher):
    yield AttachFile('hosts', '/etc/hosts')
    yield AttachFile('resolv.conf', '/etc/resolv.conf')
    yield AttachCommandOutput('ifconfig', ['/sbin/ifconfig', '-v'])
    yield AttachCommandOutput('routing-table', ['/usr/bin/netstat', '-nr'])
    yield AttachCommandOutput('arp-table', ['/usr/sbin/arp', '-an'])
    yield AttachCommandOutput('arp-table', ['/usr/sbin/arp', '-an'])
    yield AttachCommandOutput('mbuf-stats', ['/usr/bin/netstat', '-m'])
    yield AttachCommandOutput('interface-stats', ['/usr/bin/netstat', '-i'])

    for i in ['ip', 'arp', 'udp', 'tcp', 'icmp']:
        yield AttachCommandOutput('netstat-proto-{0}'.format(i), ['/usr/bin/netstat', '-p', i, '-s'])


def _depends():
    return ['DevdPlugin']


def _init(dispatcher, plugin):
    def on_resolv_conf_change(args):
        # If DNS has changed lets reset our DNS resolver to reflect reality
        logger.debug('Resetting resolver')
        del hub.get_hub().resolver
        hub.get_hub()._resolver = None

    plugin.register_schema_definition('network-interface', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'$ref': 'network-interface-type'},
            'id': {'type': 'string'},
            'name': {'type': ['string', 'null']},
            'created_at': {'type': 'datetime'},
            'updated_at': {'type': 'datetime'},
            'enabled': {'type': 'boolean'},
            'dhcp': {'type': 'boolean'},
            'rtadv': {'type': 'boolean'},
            'noipv6': {'type': 'boolean'},
            'mtu': {'type': ['integer', 'null']},
            'media': {'type': ['string', 'null']},
            'mediaopts': {'$ref': 'network-interface-mediaopts'},
            'capabilities': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'add': {'$ref': 'network-interface-capabilities'},
                    'del': {'$ref': 'network-interface-capabilities'},
                }
            },
            'aliases': {
                'type': 'array',
                'items': {'$ref': 'network-interface-alias'}
            },
            'vlan': {'$ref': 'network-interface-vlan-properties'},
            'lagg': {'$ref': 'network-interface-lagg-properties'},
            'bridge': {'$ref': 'network-interface-bridge-properties'},
            'status': {'$ref': 'network-interface-status'}
        }
    })

    plugin.register_schema_definition('network-interface-vlan-properties', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'parent': {'type': ['string', 'null']},
            'tag': {
                'type': ['integer', 'null'],
                'minimum': 1,
                'maximum': 4095
            }
        }
    })

    plugin.register_schema_definition('network-interface-lagg-properties', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'protocol': {'$ref': 'network-aggregation-protocols'},
            'ports': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('network-interface-bridge-properties', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'members': {
                'type': 'array',
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_schema_definition('network-interface-alias', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'$ref': 'network-interface-alias-type'},
            'address': {'$ref': 'ip-address'},
            'netmask': {'type': 'integer'},
            'broadcast': {
                'oneOf': [{'$ref': 'ipv4-address'}, {'type': 'null'}]
            }
        }
    })

    plugin.register_schema_definition('network-interface-alias-type', {
        'type': 'string',
        'enum': ['INET', 'INET6']
    })

    plugin.register_schema_definition('network-route', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'type': {'$ref': 'network-route-type'},
            'network': {'$ref': 'ip-address'},
            'netmask': {'type': 'integer'},
            'gateway': {'$ref': 'ip-address'}
        }
    })

    plugin.register_schema_definition('network-route-type', {
        'type': 'string',
        'enum': ['INET', 'INET6']
    })

    plugin.register_schema_definition('network-host', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'id': {'type': 'string'},
            'addresses': {
                'type': 'array',
                'items': {'$ref': 'ip-address'}
            }
        }
    })

    plugin.register_schema_definition('network-config', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'autoconfigure': {'type': 'boolean'},
            'http_proxy': {'type': ['string', 'null']},
            'gateway': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'ipv4': {'oneOf': [{'$ref': 'ipv4-address'}, {'type': 'null'}]},
                    'ipv6': {'oneOf': [{'$ref': 'ipv6-address'}, {'type': 'null'}]}
                }
            },
            'dns': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'addresses': {'type': 'array', 'items': {'$ref': 'ip-address'}},
                    'search': {'type': 'array', 'items': {'type': 'string'}}
                }
            },
            'dhcp': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'assign_gateway': {'type': 'boolean'},
                    'assign_dns': {'type': 'boolean'}
                }
            },
            'netwait': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'enabled': {'type': 'boolean'},
                    'addresses': {
                        'type': 'array',
                        'items': {'$ref': 'ip-address'}
                    }
                }
            }
        }
    })

    plugin.register_schema_definition('network-status', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'gateway': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'ipv4': {'oneOf': [{'$ref': 'ipv4-address'}, {'type': 'null'}]},
                    'ipv6': {'oneOf': [{'$ref': 'ipv6-address'}, {'type': 'null'}]}
                }
            },
            'dns': {
                'type': 'object',
                'additionalProperties': False,
                'properties': {
                    'addresses': {'type': 'array', 'items': {'$ref': 'ip-address'}},
                    'search': {'type': 'array', 'items': {'type': 'string'}}
                }
            }
        }
    })

    plugin.register_provider('network.config', NetworkProvider)
    plugin.register_provider('network.interface', InterfaceProvider)
    plugin.register_provider('network.route', RouteProvider)
    plugin.register_provider('network.host', HostsProvider)

    plugin.register_task_handler('network.config.update', NetworkConfigureTask)
    plugin.register_task_handler('network.host.create', AddHostTask)
    plugin.register_task_handler('network.host.update', UpdateHostTask)
    plugin.register_task_handler('network.host.delete', DeleteHostTask)
    plugin.register_task_handler('network.route.create', AddRouteTask)
    plugin.register_task_handler('network.route.update', UpdateRouteTask)
    plugin.register_task_handler('network.route.delete', DeleteRouteTask)
    plugin.register_task_handler('network.interface.up', InterfaceUpTask)
    plugin.register_task_handler('network.interface.down', InterfaceDownTask)
    plugin.register_task_handler('network.interface.update', ConfigureInterfaceTask)
    plugin.register_task_handler('network.interface.create', CreateInterfaceTask)
    plugin.register_task_handler('network.interface.delete', DeleteInterfaceTask)
    plugin.register_task_handler('network.interface.renew', InterfaceRenewTask)

    plugin.register_event_type('network.changed')
    plugin.register_event_type('network.config.changed')
    plugin.register_event_type('network.interface.changed')
    plugin.register_event_type('network.host.changed')
    plugin.register_event_type('network.route.changed')
    plugin.register_event_type('network.interface.attached')
    plugin.register_event_type('network.interface.detached')
    plugin.register_event_type('network.interface.mtu_changed')
    plugin.register_event_type('network.interface.link_down')
    plugin.register_event_type('network.interface.link_up')
    plugin.register_event_type('network.interface.down')
    plugin.register_event_type('network.interface.up')
    plugin.register_event_type('network.interface.flags_changed')
    plugin.register_event_type('network.route.added')
    plugin.register_event_type('network.route.deleted')
    plugin.register_event_type('network.dns.configured')
    plugin.register_event_type('network.interface.configured')

    plugin.register_event_handler('network.dns.configured', on_resolv_conf_change)

    plugin.register_debug_hook(collect_debug)
