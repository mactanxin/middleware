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
from dispatcher.rpc import RpcException, description, accepts, returns
from datastore.config import ConfigNode
from task import Provider, Task, TaskException, VerifyException, query


def calculate_broadcast(address, netmask):
    return ipaddress.ip_interface(u'{0}/{1}'.format(address, netmask)).network.broadcast_address


@description("Provides access to global network configuration settings")
class NetworkProvider(Provider):
    def get_global_config(self):
        return ConfigNode('network', self.configstore)

    def get_my_ips(self):
        ifaces = self.dispatcher.call_sync('networkd.configuration.query_interfaces')
        for i in ifaces:
            if i['type'] == 'LOOP':
                continue


class InterfaceProvider(Provider):
    @query('network-interface')
    def query(self, filter=None, params=None):
        result = []
        ifaces = self.dispatcher.call_sync('networkd.configuration.query_interfaces')

        if params and params.get('single'):
            result = self.datastore.query('network.interfaces', *(filter or []), **(params or {}))
            result['status'] = ifaces[result['name']]
            return result

        for i in self.datastore.query('network.interfaces', *(filter or []), **(params or {})):
            if i['name'] in ifaces:
                i['status'] = ifaces[i['name']]

            result.append(i)

        return result


class RouteProvider(Provider):
    @query('network-route')
    def query(self, filter=None, params=None):
        return self.datastore.query('network.routes', *(filter or []), **(params or {}))


@description("Provides access to static host entries database")
class HostsProvider(Provider):
    @query('network-host')
    def query(self, filter=None, params=None):
        return self.datastore.query('network.hosts', *(filter or []), **(params or {}))


@description("Updates global network configuration settings")
@accepts({
    'type': 'object',
    'properties': {
        'gateway': {
            'type': 'object',
            'properties': {
                'ipv4': {'type': ['string', 'null']},
                'ipv6': {'type': ['string', 'null']}
            }
        },
        'dns': {
            'type': 'object',
            'properties': {
                'servers': {'type': 'array'},
                'search': {'type': 'array'}
            }
        },
        'dhcp': {
            'type': 'object',
            'properties': {
                'assign_gateway': {'type': 'boolean'},
                'assign_dns': {'type': 'boolean'}
            }
        }
    }
})
class NetworkConfigureTask(Task):
    def verify(self, settings):
        return ['system']

    def run(self, settings):
        node = ConfigNode('network', self.dispatcher.configstore)
        node.update(settings)

        try:
            self.dispatcher.call_sync('networkd.configuration.configure_network')
            self.dispatcher.call_sync('etcd.generation.generate_group', 'network')
        except RpcException, e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure interface: {0}'.format(str(e)))


@accepts(
    {'type': 'string'},
    {'type': 'string'}
)
class CreateInterfaceTask(Task):
    def verify(self, name, type):
        if self.datastore.exists('network.interfaces', ('name', '=', name)):
            raise VerifyException(errno.EEXIST, 'Interface {0} exists'.format(name))

        return ['system']

    def run(self, name, type):
        self.datastore.insert('network.interfaces', {
            'id': name,
            'type': type
        })

        try:
            self.dispatcher.call_sync('networkd.configuration.configure_network')
        except RpcException, e:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure network: {0}'.format(str(e)))


@description("Deletes interface")
@accepts({
    'type': 'string',
    'title': 'name'
})
class DeleteInterfaceTask(Task):
    def verify(self, name):
        raise NotImplementedError()

    def run(self, name):
        raise NotImplementedError()


@description("Alters network interface configuration")
@accepts({
    'type': 'string',
    'title': 'name'
}, {
    '$ref': 'network-interface'
})
class ConfigureInterfaceTask(Task):
    def verify(self, name, updated_fields):
        if not self.datastore.exists('network.interfaces', ('name', '=', name)):
            raise VerifyException(errno.ENOENT, 'Interface {0} does not exist'.format(name))

        return ['system']

    def run(self, name, updated_fields):
        if updated_fields.get('dhcp'):
            # Check for DHCP inconsistencies
            # 1. Check whether DHCP is enabled on other interfaces
            # 2. Check whether DHCP configures default route and/or DNS server addresses
            dhcp_used = self.datastore.exists('network.interfaces', ('dhcp', '=', True), ('id' '!=', name))
            dhcp_global = self.dispatcher.configstore.get('network.dhcp.assign_gateway') or \
                self.dispatcher.configstore.get('network.dhcp.assign_dns')

            if dhcp_used and dhcp_global:
                raise TaskException(errno.ENXIO, 'DHCP is already configured on another interface')

        if updated_fields.get('aliases'):
            # Check for aliases inconsistencies
            ips = [x['address'] for x in updated_fields['aliases']]
            if any(ips.count(x) > 1 for x in ips):
                raise TaskException(errno.ENXIO, 'Duplicated IP alias')

            # Add missing broadcast addresses and address family
            for i in updated_fields['aliases']:
                i['type'] = i.get('type', 'INET')
                if not i.get('broadcast'):
                    i['broadcast'] = str(calculate_broadcast(i['address'], i['netmask']))

        entity = self.datastore.get_by_id('network.interfaces', name)
        entity.update(updated_fields)
        self.datastore.update('network.interfaces', name, entity)

        try:
            self.dispatcher.call_sync('networkd.configuration.configure_interface', name)
        except RpcException:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure interface, networkd service is offline')

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'update',
            'ids': [name]
        })


@description("Enables interface")
@accepts({
    'type': 'string',
    'title': 'name'
})
class InterfaceUpTask(Task):
    def verify(self, name):
        if not self.datastore.exists('network.interfaces', ('name', '=', name)):
            raise VerifyException(errno.ENOENT, 'Interface {0} does not exist'.format(name))

        return ['system']

    def run(self, name):
        try:
            self.dispatcher.call_sync('networkd.configuration.up_interface', name)
        except RpcException:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure interface, networkd service is offline')

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'update',
            'ids': [name]
        })


@description("Disables interface")
@accepts({
    'type': 'string',
    'title': 'name'
})
class InterfaceDownTask(Task):
    def verify(self, name):
        if not self.datastore.exists('network.interfaces', ('name', '=', name)):
            raise VerifyException(errno.ENOENT, 'Interface {0} does not exist'.format(name))

        return ['system']

    def run(self, name):
        try:
            self.dispatcher.call_sync('networkd.configuration.down_interface', name)
        except RpcException:
            raise TaskException(errno.ENXIO, 'Cannot reconfigure interface, networkd service is offline')

        self.dispatcher.dispatch_event('network.interface.changed', {
            'operation': 'update',
            'ids': [name]
        })


@description("Adds host entry to the database")
@accepts({
    'type': 'string',
    'title': 'name'
}, {
    'type': 'string',
    'title': 'address'
})
class AddHostTask(Task):
    def verify(self, name, address):
        if self.datastore.exists('network.hosts', ('id', '=', name)):
            raise VerifyException(errno.EEXIST, 'Host entry {0} already exists'.format(name))
        return ['system']

    def run(self, name, address):
        self.datastore.insert('network.hosts', {
            'id': name,
            'address': address
        })

        try:
            self.dispatcher.call_sync('etcd.generation.generate_group', 'network')
        except RpcException, e:
            raise TaskException(errno.ENXIO, 'Cannot regenerate groups file, etcd service is offline')

        self.dispatcher.dispatch_event('network.host.changed', {
            'operation': 'create',
            'ids': [name]
        })


@description("Updates host entry in the database")
@accepts({
    'type': 'string',
    'title': 'name'
}, {
    'type': 'string',
    'title': 'address'
})
class UpdateHostTask(Task):
    def verify(self, name, address):
        if not self.datastore.exists('network.hosts', ('id', '=', name)):
            raise VerifyException(errno.ENOENT, 'Host entry {0} does not exists'.format(name))

        return ['system']

    def run(self, name, address):
        host = self.datastore.get_one('network.hosts', ('id', '=', name))
        host['address'] = address
        self.datastore.update('network.hosts', host['id'], host)

        try:
            self.dispatcher.call_sync('etcd.generation.generate_group', 'network')
        except RpcException, e:
            raise TaskException(errno.ENXIO, 'Cannot regenerate groups file, etcd service is offline')

        self.dispatcher.dispatch_event('network.host.changed', {
            'operation': 'update',
            'ids': [name]
        })


@description("Deletes host entry from the database")
@accepts({
    'type': 'string',
    'title': 'name'
})
class DeleteHostTask(Task):
    def verify(self, name):
        if not self.datastore.exists('network.hosts', ('id', '=', name)):
            raise VerifyException(errno.ENOENT, 'Host entry {0} does not exists'.format(name))

        return ['system']

    def run(self, name):
        self.datastore.delete('network.hosts', name)

        try:
            self.dispatcher.call_sync('etcd.generation.generate_group', 'network')
        except RpcException, e:
            raise TaskException(errno.ENXIO, 'Cannot regenerate groups file, etcd service is offline')

        self.dispatcher.dispatch_event('network.host.changed', {
            'operation': 'delete',
            'ids': [name]
        })


@description("Adds static route to the system")
@accepts({
    '$ref': 'network-route',
    'title': 'route'
})
class AddRouteTask(Task):
    def verify(self, route):
        if self.datastore.exists('network.routes', ('id', '=', route['id'])):
            raise VerifyException(errno.EEXIST, 'Route {0} exists'.format(route['id']))

        return ['system']

    def run(self, route):
        id = self.datastore.insert('network.routes', route)
        self.dispatcher.dispatch_event('network.route.changed', {
            'operation': 'create',
            'ids': [id]
        })


@description("Updates static route in the system")
@accepts({
    'type': 'string',
    'title': 'name'
}, {
    '$ref': 'network-route',
    'title': 'route'
})
class UpdateRouteTask(Task):
    def verify(self, name, route):
        if not self.datastore.exists('network.routes', ('id', '=', name)):
            raise VerifyException(errno.ENOENT, 'Route {0} does not exists'.format(name))

        return ['system']

    def run(self, name, updated_fields):
        route = self.datastore.get_one('network.routes', ('id', '=', name))
        route.update(updated_fields)
        self.datastore.update('network.routes', name, updated_fields)

        self.dispatcher.dispatch_event('network.route.changed', {
            'operation': 'update',
            'ids': [route['id']]
        })


@description("Deletes static route from the system")
@accepts({
    '$ref': 'string',
    'title': 'name'
})
class DeleteRouteTask(Task):
    def verify(self, name):
        if not self.datastore.exists('network.routes', ('id', '=', name)):
            raise VerifyException(errno.ENOENT, 'route {0} does not exists'.format(name))

        return ['system']

    def run(self, name):
        self.dispatcher.dispatch_event('network.route.changed', {
            'operation': 'update',
            'ids': [None]
        })


def _depends():
    return ['DevdPlugin']


def _init(dispatcher):
    dispatcher.register_schema_definition('network-interface', {
        'type': 'object',
        'properties': {
            'type': {'type': 'string'},
            'name': {'type': 'string'},
            'enabled': {'type': 'boolean'},
            'dhcp': {'type': 'boolean'},
            'mtu': {'type': ['integer', 'null']},
            'aliases': {
                'type': 'array',
                'items': {'type': 'network-interface-alias'}
            },
            'status': {
                'type': 'object',
                'properties': {

                }
            }
        }
    })

    dispatcher.register_schema_definition('network-interface-alias', {
        'type': 'object',
        'properties': {
            'type': {
                'type': 'string',
                'enum': [
                    'INET',
                    'INET6'
                ]
            },
            'address': {'type': 'string'},
            'prefixlen': {'type': 'integer'},
            'broadcast': {'type': ['string', 'null']}
        }
    })

    dispatcher.register_schema_definition('network-route', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'type': {'type': 'string', 'enum': ['INET', 'INET6']},
            'network': {'type': 'string'},
            'netmask': {'type': 'integer'},
            'gateway': {'type': 'string'}
        }
    })

    dispatcher.register_schema_definition('network-host', {
        'type': 'object',
        'properties': {
            'address': {'type': 'string'},
            'name': {'type': 'string'}
        }
    })

    dispatcher.require_collection('network.interfaces')
    dispatcher.require_collection('network.routes')
    dispatcher.require_collection('network.hosts')

    dispatcher.register_provider('network.config', NetworkProvider)
    dispatcher.register_provider('network.interfaces', InterfaceProvider)
    dispatcher.register_provider('network.routes', RouteProvider)
    dispatcher.register_provider('network.hosts', HostsProvider)

    dispatcher.register_task_handler('network.configure', NetworkConfigureTask)
    dispatcher.register_task_handler('network.host.add', AddHostTask)
    dispatcher.register_task_handler('network.host.update', UpdateHostTask)
    dispatcher.register_task_handler('network.host.delete', DeleteHostTask)
    dispatcher.register_task_handler('network.route.add', AddRouteTask)
    dispatcher.register_task_handler('network.route.update', UpdateRouteTask)
    dispatcher.register_task_handler('network.route.delete', DeleteRouteTask)
    dispatcher.register_task_handler('network.interface.up', InterfaceUpTask)
    dispatcher.register_task_handler('network.interface.down', InterfaceDownTask)
    dispatcher.register_task_handler('network.interface.configure', ConfigureInterfaceTask)
    dispatcher.register_task_handler('network.interface.create', CreateInterfaceTask)
    dispatcher.register_task_handler('network.interface.delete', DeleteInterfaceTask)


