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
import logging
import sqlite3
import datetime
from time import sleep
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
    TaskDescription,
    VerifyException
)

logger = logging.getLogger('MigrationPlugin')
sys.path.append('/usr/local/lib')
FREENAS93_DATABASE_PATH = '/data/freenas-v1.db'
NOGROUP_ID = '8980c534-6a71-4bfb-bc72-54cbd5a186db'
# We need to set this env var before any migrate93 based imports
os.environ['93_DATABASE_PATH'] = FREENAS93_DATABASE_PATH
from migrate93.src.utils import run_syncdb


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
            ('bsdgrp_gid', '=', groups[root_user['bsdusr_group_id']]['bsdgrp_gid']),
            single=True
        )
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
        aux_groups = q.query(fn10_groups, ('gid', 'in', aux_groups), select=['id'])
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
        'fullname': fn9_user['bsdusr_full_name'],
        'password_disabled': bool(fn9_user['bsdusr_password_disabled']),
        'locked': bool(fn9_user['bsdusr_locked']),
        'shell': fn9_user['bsdusr_shell'],
        'home': fn9_user['bsdusr_home'],
        'sudo': bool(fn9_user['bsdusr_sudo']),
        'email': fn9_user['bsdusr_email'],
        'lmhash': lmhash,
        'nthash': nthash,
        'password_changed_at': password_changed_at
    })
    return user


@description("Accounts (users and groups) migration task")
class AccountsMigrateTask(Task):
    @classmethod()
    def early_describe(cls):
        return "Migration of FreeNAS 9.x users and grups to 10.x"

    def descrive(self):
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
        del fn10_root_user['builtin']
        fn10_root_user = populate_user_obj(fn10_root_user, fn10_groups, root_user, groups, grp_membership)
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
    @classmethod()
    def early_describe(cls):
        return "Migration of FreeNAS 9.x network settings to 10.x"

    def descrive(self):
        return TaskDescription("Migration of FreeNAS 9.x network settings to 10.x")

    def run(self):
        pass

@description("Master top level migration task for 9.x to 10.x")
class MasterMigrateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x settings to 10"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x settings to 10")

    def run(self):
        logger.debug("Starting migration from 9.x database to 10")
        self.dispatcher.dispatch_event(
            'migration.status',
            {
                'apps_migrated': [],
                'status': 'STARTED'
            }
        )
        # bring the 9.x database up to date with the latest 9.x version
        run_syncdb()
        self.dispatcher.dispatch_event(
            'migration.status',
            {
                'apps_migrated': ['accounts', 'network'],
                'status': 'RUNNING'
            }
        )
        # for now put a dummy sleep here
        sleep(10)
        # If we reached till here migration must have succeeded
        # so lets rename the databse
        os.rename(FREENAS93_DATABASE_PATH, "{0}.done".format(FREENAS93_DATABASE_PATH))
        # send out finished event
        self.dispatcher.dispatch_event(
            'migration.status',
            {
                'apps_migrated': [
                    'accounts', 'network', 'directoryservice', 'support', 'services', 'sharing',
                    'storage', 'system', 'tasks'
                ],
                'status': 'FINISHED'
            }
        )


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
        dispatcher.call_task_sync('migration.mastermigrate')
    else:
        dispatcher.dispatch_event(
            'migration.status',
            {
                'apps_migrated': [],
                'status': 'NOT_NEEDED'
            }
        )
