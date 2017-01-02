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
import logging
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


@description("Master top level migration task for 9.x to 10.x")
class MasterMigrateTask(ProgressTask):
    @classmethod
    def early_describe(cls):
        return "Migration of FreeNAS 9.x settings to 10"

    def describe(self):
        return TaskDescription("Migration of FreeNAS 9.x settings to 10")

    def run(self):
        pass


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
        logger.debug("Starting migration from 9.x database to 10")
        # TODO: PLace migrate93 syncdb call here
        dispatcher.call_task_sync('migration.mastermigrate')

    if os.path.exists("/data/freenas-v1.db"):
        plugin.register_event_handler('service.ready', start_migration)

    plugin.register_task_handler('migration.mastermigrate', MasterMigrateTask)
