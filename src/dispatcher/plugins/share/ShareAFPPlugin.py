#+
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

import os
import bsd
import pwd
import signal
from task import Task, TaskWarning, Provider, TaskDescription
from freenas.dispatcher.rpc import description, accepts, private
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.utils import first_or_default, normalize


@description("Provides info about configured AFP shares")
class AFPSharesProvider(Provider):
    @private
    def get_connected_clients(self, blah=None):
        result = []
        shares = self.dispatcher.call_sync('share.query', [('type', '=', 'afp')])
        for proc in bsd.getprocs(bsd.ProcessLookupPredicate.PROC):
            if proc.command != 'afpd':
                continue

            def test_descriptor(d):
                if d.type != bsd.DescriptorType.SOCKET:
                    return False

                if not d.local_address:
                    return False

                return d.local_address[1] == 548

            cnid_pid = None
            path = proc.cwd
            share = first_or_default(lambda s: s['filesystem_path'] == path, shares)
            sock = first_or_default(test_descriptor, proc.files)
            if not share or not sock:
                continue

            # Look up the cnid_dbd process too
            for p in bsd.getprocs(bsd.ProcessLookupPredicate.PROC):
                if p.command == 'cnid_dbd' and p.cwd == os.path.join(path, '.AppleDB'):
                    cnid_pid = p.pid

            try:
                u = pwd.getpwuid(proc.uid)
                user = u.pw_name
            except KeyError:
                user = str(proc.uid)

            result.append({
                'host': str(sock.peer_address[0]),
                'share': share['name'],
                'user': user,
                'connected_at': proc.started_at,
                'extra': {
                    'pid': proc.pid,
                    'cnid_dbd_pid': cnid_pid
                }
            })

        return result


@private
@accepts(h.ref('share'))
@description("Adds new AFP share")
class CreateAFPShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating AFP share"

    def describe(self, share):
        return TaskDescription("Creating AFP share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        return ['service:afp']

    def run(self, share):
        normalize(share['properties'], {
            'read_only': False,
            'time_machine': False,
            'zero_dev_numbers': False,
            'no_stat': False,
            'afp3_privileges': True,
            'ro_users': None,
            'ro_groups': None,
            'rw_users': None,
            'rw_groups': None,
            'users_allow': None,
            'users_deny': None,
            'groups_allow': None,
            'groups_deny': None,
            'hosts_allow': None,
            'hosts_deny': None,
            'default_file_perms': None,
            'default_directory_perms': None,
            'default_umask': None
        })

        id = self.datastore.insert('shares', share)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'afp')
        self.dispatcher.call_sync('service.reload', 'afp', timeout=60)
        self.dispatcher.dispatch_event('share.afp.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id


@private
@accepts(str, h.ref('share'))
@description("Updates existing AFP share")
class UpdateAFPShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating AFP share"

    def describe(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Updating AFP share {name}", name=share.get('name', id) if share else id)

    def verify(self, id, updated_fields):
        return ['service:afp']

    def run(self, id, updated_fields):
        share = self.datastore.get_by_id('shares', id)
        share.update(updated_fields)
        self.datastore.update('shares', id, share)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'afp')
        self.dispatcher.call_sync('service.reload', 'afp', timeout=60)
        self.dispatcher.dispatch_event('share.afp.changed', {
            'operation': 'update',
            'ids': [id]
        })


@private
@accepts(str)
@description("Removes AFP share")
class DeleteAFPShareTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting AFP share"

    def describe(self, id):
        share = self.datastore.get_by_id('shares', id)
        return TaskDescription("Deleting AFP share {name}", name=share.get('name', id) if share else id)

    def verify(self, id):
        return ['service:afp']

    def run(self, id):
        share = self.datastore.get_by_id('shares', id)

        for w in kill_connections(self.dispatcher, lambda c: c['share'] == share['name']):
            self.add_warning(w)

        self.datastore.delete('shares', id)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'afp')
        self.dispatcher.call_sync('service.reload', 'afp', timeout=60)
        self.dispatcher.dispatch_event('share.afp.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@private
@accepts(h.ref('share'))
@description("Imports existing AFP share")
class ImportAFPShareTask(CreateAFPShareTask):
    @classmethod
    def early_describe(cls):
        return "Importing AFP share"

    def describe(self, share):
        return TaskDescription("Importing AFP share {name}", name=share.get('name', '') if share else '')

    def verify(self, share):
        return super(ImportAFPShareTask, self).verify(share)

    def run(self, share):
        return super(ImportAFPShareTask, self).run(share)


@description('Terminates AFP connection')
class TerminateAFPConnectionTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Terminating AFP connection'

    def describe(self, address):
        return TaskDescription('Terminating AFP connection from {name}', name=address)

    def verify(self, address):
        return ['system']

    def run(self, address):
        for w in kill_connections(self.dispatcher, lambda c: c['host'] == address):
            self.add_warning(w)


def kill_connections(dispatcher, predicate):
    for c in dispatcher.call_sync('share.afp.get_connected_clients'):
        if predicate(c):
            pid = c['extra']['pid']
            cnid_dbd_pid = c['extra']['cnid_dbd_pid']
            try:
                os.kill(pid, signal.SIGTERM)
                if cnid_dbd_pid:
                    os.kill(cnid_dbd_pid, signal.SIGTERM)
            except OSError as err:
                yield TaskWarning(err.errno, 'Cannot kill PID {0}: {1}'.format(pid, str(err)))


def _depends():
    return ['AFPPlugin', 'SharingPlugin']


def _metadata():
    return {
        'type': 'sharing',
        'subtype': 'FILE',
        'perm_type': 'PERM',
        'method': 'afp'
    }


def _init(dispatcher, plugin):
    plugin.register_schema_definition('share-afp', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['share-afp']},
            'comment': {'type': 'string'},
            'read_only': {'type': 'boolean'},
            'time_machine': {'type': 'boolean'},
            'zero_dev_numbers': {'type': 'boolean'},
            'no_stat': {'type': 'boolean'},
            'afp3_privileges': {'type': 'boolean'},
            'default_file_perms': {
                'oneOf': [{'$ref': 'unix-permissions'}, {'type': 'null'}]
            },
            'default_directory_perms': {
                'oneOf': [{'$ref': 'unix-permissions'}, {'type': 'null'}]
            },
            'default_umask': {
                'oneOf': [{'$ref': 'unix-permissions'}, {'type': 'null'}]
            },
            'ro_users': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'ro_groups': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'rw_users': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'rw_groups': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'users_allow': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'users_deny': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'groups_allow': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'groups_deny': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'hosts_allow': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            },
            'hosts_deny': {
                'type': ['array', 'null'],
                'items': {'type': 'string'}
            }
        }
    })

    plugin.register_task_handler("share.afp.create", CreateAFPShareTask)
    plugin.register_task_handler("share.afp.update", UpdateAFPShareTask)
    plugin.register_task_handler("share.afp.delete", DeleteAFPShareTask)
    plugin.register_task_handler("share.afp.import", ImportAFPShareTask)
    plugin.register_task_handler("share.afp.terminate_connection", TerminateAFPConnectionTask)
    plugin.register_provider("share.afp", AFPSharesProvider)
    plugin.register_event_type('share.afp.changed')
