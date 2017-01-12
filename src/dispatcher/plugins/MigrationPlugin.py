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
from time import sleep
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

# We need to set this env var before any migrate93 based imports
os.environ['93_DATABASE_PATH'] = FREENAS93_DATABASE_PATH
from migrate93.src.utils import run_syncdb


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
