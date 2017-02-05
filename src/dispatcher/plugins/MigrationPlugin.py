#
# Copyright 2016 iXsystems, Inc.
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
import re
import ipaddress
import logging
import sqlite3
import datetime
import errno
from freenas.serviced import push_status
from freenas.utils import query as q
from freenas.dispatcher.rpc import (
    RpcException,
    SchemaHelper as h,
    accepts,
    description,
    returns
)
from task import (
    Task,
    ProgressTask,
    TaskException,
    TaskWarning,
    TaskDescription
)

logger = logging.getLogger('MigrationPlugin')
sys.path.append('/usr/local/lib')
FREENAS93_DATABASE_PATH = '/data/freenas-v1.db'
NOGROUP_ID = '8980c534-6a71-4bfb-bc72-54cbd5a186db'
# We need to set this env var before any migrate93 based imports
os.environ['93_DATABASE_PATH'] = FREENAS93_DATABASE_PATH
from migrate93.src.utils import run_syncdb


LAGG_PROTOCOL_MAP = {
    'failover': 'FAILOVER',
    'fec': 'ETHERCHANNEL',
    'lacp': 'LACP',
    'loadbalance': 'LOADBALANCE',
    'roundrobin': 'ROUNDROBIN',
    'none': 'NONE'
}


MEDIAOPT_MAP = {
    'full-duplex': 'FDX',
    'half-duplex': 'HDX'
}


CAPABILITY_MAP = {
    'rxcsum': ('RXCSUM',),
    'txcsum': ('TXCSUM',),
    'rxcsum6': ('RXCSUM_IPV6',),
    'txcsum6': ('TXCSUM_IPV6',),
    'tso': ('TSO4', 'TSO6'),
    'tso4': ('TSO4',),
    'tso6': ('TSO6',),
    'lro': ('LRO',)
}


def get_table(query_string, dictionary=True):
    with sqlite3.connect(FREENAS93_DATABASE_PATH) as conn:
        cursor = conn.cursor()
        res = cursor.execute(query_string)
        header_names = [desc[0] for desc in res.description]
        data = res.fetchall()
        formatted_result = [
            {name: entry[i] for i, name in enumerate(header_names)} for entry in data
        ]
        if dictionary:
            formatted_result = {entry['id']: entry for entry in formatted_result}
        return formatted_result


def populate_user_obj(user, fn10_groups, fn9_user, fn9_groups, fn9_grpmem):

    if user is None:
        user = {}

    pubkeys = None
    try:
        with open('%s/.ssh/authorized_keys' % fn9_user['bsdusr_home'], 'r') as f:
            pubkeys = f.read()
    except:
        pass

    try:
        grp = q.query(
            fn10_groups,
            ('gid', '=', fn9_groups[fn9_user['bsdusr_group_id']]['bsdgrp_gid']),
            single=True
        )['id']
    except:
        logger.debug(
            'Got exception whilst trying to lookup group for user: {0}'.format(fn9_user),
            exc_info=True
        )
        grp = NOGROUP_ID

    lmhash = nthash = password_changed_at = None
    if fn9_user['bsdusr_smbhash']:
        try:
            pieces = fn9_user['bsdusr_smbhash'].strip().split(':')
            lmhash = pieces[2]
            nthash = pieces[3]
            password_changed_at = datetime.datetime.fromtimestamp(int(pieces[5].split('-')[1], 16))
        except:
            pass

    try:
        aux_groups = [
            fn9_groups[item['bsdgrpmember_group_id']]['bsdgrp_gid']
            for item in fn9_grpmem.values() if item['bsdgrpmember_user_id'] == fn9_user['id']
        ]
        aux_groups = [item[0] for item in q.query(fn10_groups, ('gid', 'in', aux_groups), select=['id'])]
    except:
        logger.debug(
            'Got exception whilst trying to populate aux groups for user: {0}'.format(fn9_user),
            exc_info=True
        )
        aux_groups = []

    user.update({
        'sshpubkey': pubkeys,
        'username': fn9_user['bsdusr_username'],
        'group': grp,
        'groups': aux_groups,
        'unixhash': fn9_user['bsdusr_unixhash'],
        'full_name': fn9_user['bsdusr_full_name'],
        'password_disabled': bool(fn9_user['bsdusr_password_disabled']),
        'locked': bool(fn9_user['bsdusr_locked']),
        'shell': fn9_user['bsdusr_shell'],
        # 'home': fn9_user['bsdusr_home'],
        'sudo': bool(fn9_user['bsdusr_sudo']),
        'email': fn9_user['bsdusr_email'],
        'lmhash': lmhash,
        'nthash': nthash,
        'password_changed_at': password_changed_at
    })
    return user


@description("Accounts (users and groups) migration task")
class AccountsMigrateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x users and grups to 10.x"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x users and groups to 10.x")

    def run(self):
        users = get_table('select * from account_bsdusers')
        groups = get_table('select * from account_bsdgroups')
        grp_membership = get_table('select * from account_bsdgroupmembership')

        # First lets create all the non buitlin groups in this system
        group_subtasks = []
        for g in filter(lambda x: x['bsdgrp_builtin'] == 0, groups.values()):
            group_subtasks.append(self.run_subtask(
                'group.create',
                {
                    'name': g['bsdgrp_group'],
                    'gid': g['bsdgrp_gid'],
                    'sudo': g['bsdgrp_sudo']
                }
            ))
        if group_subtasks:
            self.join_subtasks(*group_subtasks)

        # Now lets first add the root user's properties (password, etc)
        fn10_groups = list(self.dispatcher.call_sync('group.query'))
        root_user = users.pop(1)
        fn10_root_user = self.dispatcher.call_sync(
            'user.query', [('uid', '=', 0)], {"single": True}
        )
        fn10_root_user = populate_user_obj(fn10_root_user, fn10_groups, root_user, groups, grp_membership)
        del fn10_root_user['builtin']
        del fn10_root_user['home']
        del fn10_root_user['uid']
        del fn10_root_user['username']
        del fn10_root_user['locked']
        self.run_subtask_sync('user.update', fn10_root_user['id'], fn10_root_user)

        # Now rest of the users can be looped upon
        user_subtasks = []
        for u in filter(lambda x: x['bsdusr_builtin'] == 0, users.values()):
            user_subtasks.append(self.run_subtask(
                'user.create',
                populate_user_obj(None, fn10_groups, u, groups, grp_membership)
            ))

        if user_subtasks:
            self.join_subtasks(*user_subtasks)


@description("Network migration task")
class NetworkMigrateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x network settings to 10.x"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x network settings to 10.x")

    def run(self):
        # Lets first get all the fn9 network config data we need
        fn9_globalconf = get_table('select * from network_globalconfiguration', dictionary=False)[0]
        fn9_interfaces = get_table('select * from network_interfaces')
        fn9_aliases = get_table('select * from network_alias')
        fn9_lagg_interfaces = get_table('select * from network_lagginterface')
        fn9_lagg_membership = get_table('select * from network_lagginterfacemembers')
        fn9_static_routes = get_table('select * from network_staticroute')
        fn9_vlan = get_table('select * from network_vlan')

        # Now get the fn10 data on netowrk config and interfaces (needed to update interfaces, etc)
        fn10_interfaces = list(self.dispatcher.call_sync('network.interface.query'))

        # Now start with the conversion logic

        # Migrating regular network interfaces
        interfaces_subtasks = []
        for fn9_iface in fn9_interfaces.values():
            fn10_iface = q.query(
                fn10_interfaces, ('id', '=', fn9_iface['int_interface']), single=True
            )
            if fn10_iface:
                del fn10_iface['status']
                del fn10_iface['type']
            else:
                self.add_warning(TaskWarning(
                    errno.EINVAL,
                    'Skipping FreeNAS 9.x netwrok interface: {0} as it is not found'.format(
                        fn9_iface['int_interface']
                    )
                ))
                continue
            aliases = []
            if fn9_iface['int_ipv4address']:
                aliases.append({
                    'type': 'INET',
                    'address': fn9_iface['int_ipv4address'],
                    'netmask': int(fn9_iface['int_v4netmaskbit'])
                })
            if fn9_iface['int_ipv6address']:
                aliases.append({
                    'type': 'INET6',
                    'address': fn9_iface['int_ipv6address'],
                    'netmask': int(fn9_iface['int_v6netmaskbit'])
                })
            # # TODO: Fix below code to work
            # for alias in fn9_aliases.values():
            #     if alias['alias_v4address']:
            #         aliases.append({
            #             'type': 'INET',
            #             'address': alias['alias_v4address'],
            #             'netmask': int(alias['alias_v4netmaskbit'])
            #         })

            #     if alias.alias_v6address:
            #         aliases.append({
            #             'type': 'INET6',
            #             'address': alias['alias_v6address'],
            #             'netmask': int(alias['alias_v6netmaskbit'])
            #         })

            fn10_iface.update({
                'name': fn9_iface['int_name'],
                'dhcp': fn9_iface['int_dhcp'],
                'aliases': aliases
            })
            m = re.search(r'mtu (\d+)', fn9_iface['int_options'])
            if m:
                fn10_iface['mtu'] = int(m.group(1))

            m = re.search(r'media (\w+)', fn9_iface['int_options'])
            if m:
                fn10_iface['media'] = m.group(1)

            m = re.search(r'mediaopt (\w+)', fn9_iface['int_options'])
            if m:
                opt = m.group(1)
                if opt in MEDIAOPT_MAP:
                    fn10_iface['mediaopts'] = [MEDIAOPT_MAP[opt]]

            # Try to read capabilities
            for k, v in CAPABILITY_MAP.items():
                if '-{0}'.format(k) in fn9_iface['int_options']:
                    l = fn10_iface.setdefault('capabilities', {}).setdefault('del', [])
                    l += v
                elif k in fn9_iface['int_options']:
                    l = fn10_iface.setdefault('capabilities', {}).setdefault('add', [])
                    l += v
            interfaces_subtasks.append(self.run_subtask(
                'network.interface.update', fn10_iface.pop('id'), fn10_iface
            ))

        # TODO: Migrate LAGG interfaces
        # for key, value in fn9_lagg_interfaces

        # TODO: Migrate VLANs
        # for key, value in fn9_vlan:
        #     pass

        if interfaces_subtasks:
            self.join_subtasks(*interfaces_subtasks)

        # Migrating hosts database
        host_subtasks = []
        for line in fn9_globalconf['gc_hosts'].split('\n'):
            line = line.strip()
            if line:
                ip, *names = line.split(' ')
                host_subtasks.extend([
                    self.run_subtask('network.host.create', {'id': name, 'addresses': [ip]})
                    for name in names
                ])

        if host_subtasks:
            self.join_subtasks(*host_subtasks)

        # Migrating static routes
        route_subtasks = []
        for route in fn9_static_routes.values():
            try:
                net = ipaddress.ip_network(route['sr_destination'])
            except ValueError as e:
                logger.debug("Invalid network {0}: {1}".format(route['sr_destination'], e))
                continue

            route_subtasks.append(self.run_subtask('network.route.create', {
                'id': route['sr_description'],
                'type': 'INET',
                'network': str(net.network_address),
                'netmask': net.prefixlen,
                'gateway': route['sr_gateway'],
            }))

        if route_subtasks:
            self.join_subtasks(*route_subtasks)

        # Set the system hostname
        self.run_subtask_sync(
            'system.general.update',
            {'hostname': fn9_globalconf['gc_hostname'] + '.' + fn9_globalconf['gc_domain']}
        )

        # Finally migrate the global network config
        gc_nameservers = [
            fn9_globalconf['gc_nameserver' + x] for x in ['1', '2', '3']
            if fn9_globalconf['gc_nameserver' + x]
        ]
        self.run_subtask_sync(
            'network.config.update',
            {
                'autoconfigure': bool(fn9_interfaces),
                'http_proxy': fn9_globalconf['gc_httpproxy'] or None,
                'gateway': {
                    'ipv4': fn9_globalconf['gc_ipv4gateway'] or None,
                    'ipv6': fn9_globalconf['gc_ipv6gateway'] or None
                },
                'dns': {'addresses': gc_nameservers},
                'dhcp': {
                    'assign_gateway': not bool(
                        fn9_globalconf['gc_ipv4gateway'] or fn9_globalconf['gc_ipv6gateway']
                    ),
                    'assign_dns': not bool(gc_nameservers)
                },
                'netwait': {
                    'enabled': bool(fn9_globalconf['gc_netwait_enabled']),
                    'addresses': list(filter(None, fn9_globalconf['gc_netwait_ip'].split(' ')))
                }
            }
        )


@description("Master top level migration task for 9.x to 10.x")
class MasterMigrateTask(ProgressTask):
    def __init__(self, dispatcher):
        super(MasterMigrateTask, self).__init__(dispatcher)
        self.status = 'STARTED'
        self.apps_migrated = []

    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x settings to 10"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x settings to 10")

    def migration_progess(self, progress, message):
        self.set_progress(progress, message)
        self.dispatcher.dispatch_event(
            'migration.status',
            {
                'apps_migrated': self.apps_migrated,
                'status': self.status
            }
        )
        push_status(
            'MigrationPlugin: status: {0}, apps migrated: {1}'.format(
                self.status, ', '.join(self.apps_migrated)
            )
        )

    def verify(self):
        return ['system']

    def run(self):
        self.migration_progess(0, 'Starting migration from 9.x database to 10.x')

        # bring the 9.x database up to date with the latest 9.x version
        run_syncdb()

        self.status = 'RUNNING'

        self.migration_progess(0, 'Migrating account app: users and groups')
        self.run_subtask_sync('migration.accountsmigrate')
        self.apps_migrated.append('accounts')

        self.migration_progess(
            10, 'Migrating netwrok app: network config, interfaces, vlans, bridges, and laggs'
        )
        self.run_subtask_sync('migration.networkmigrate')
        self.apps_migrated.append('network')

        # If we reached till here migration must have succeeded
        # so lets rename the databse
        os.rename(FREENAS93_DATABASE_PATH, "{0}.done".format(FREENAS93_DATABASE_PATH))

        self.apps_migrated = [
            'accounts', 'network', 'directoryservice', 'support', 'services', 'sharing', 'storage',
            'system', 'tasks'
        ]
        self.status = 'FINISHED'
        self.migration_progess(100, 'Migration of FreeNAS 9.x database config and settings done')


def _depends():
    return [
        'UserPlugin', 'NetworkPlugin', 'VolumePlugin', 'AlertPlugin',
        'ShareISCSIPlugin', 'ShareNFSPlugin', 'ShareAFPPlugin', 'ShareSMBPlugin',
        'ShareWebDAVPlugin', 'IPMIPlugin', 'NTPPlugin', 'SupportPlugin',
        'SystemDatasetPlugin', 'SystemInfoPlugin', 'FTPPlugin', 'TFTPPlugin',
        'UpdatePlugin', 'CryptoPlugin', 'UPSPlugin', 'BootPlugin',
        'KerberosPlugin', 'KerberosPlugin', 'CalendarTasksPlugin', 'RsyncdPlugin',
        'ServiceManagePlugin', 'SNMPPlugin', 'SSHPlugin', 'TunablePlugin',
        'MailPlugin', 'LLDPPlugin', 'DynDNSPlugin', 'DirectoryServicePlugin'
    ]


def _init(dispatcher, plugin):

    def start_migration(args):
        logger.debug('Starting migration from 9.x database to 10.x')
        dispatcher.call_task_sync('migration.mastermigrate')

    plugin.register_schema_definition('migration-status', {
        'type': 'object',
        'properties': {
            'apps_migrated': {
                'type': 'array',
                'items': {'type': 'string'},
            },
            'status': {
                'type': 'string',
                'enum': ['NOT_NEEDED', 'STARTED', 'RUNNING', 'FINISHED']}
        }
    })

    plugin.register_task_handler('migration.mastermigrate', MasterMigrateTask)
    plugin.register_task_handler('migration.accountsmigrate', AccountsMigrateTask)
    plugin.register_task_handler('migration.networkmigrate', NetworkMigrateTask)

    plugin.register_event_type('migration.status')

    if os.path.exists(FREENAS93_DATABASE_PATH):
        plugin.register_event_handler('service.ready', start_migration)
    else:
        dispatcher.dispatch_event(
            'migration.status',
            {
                'apps_migrated': [],
                'status': 'NOT_NEEDED'
            }
        )
        push_status('MigrationPlugin: Migration not needed')
