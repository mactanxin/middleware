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

import errno
import krb5
from freenas.dispatcher.rpc import SchemaHelper as h, accepts, generator
from task import Task, TaskException, Provider, query
from debug import AttachFile, AttachCommandOutput
from freenas.utils import query as q


class KerberosRealmsProvider(Provider):
    @query('kerberos-realm')
    @generator
    def query(self, filter=None, params=None):
        return q.query(
            list(self.dispatcher.call_sync('dscached.management.get_realms')) + self.datastore.query('kerberos.realms'),
            *(filter or []),
            stream=True,
            **(params or {})
        )


class KerberosKeytabsProvider(Provider):
    @query('kerberos-keytab')
    @generator
    def query(self, filter=None, params=None):
        ctx = krb5.Context()

        def extend(keytab):
            keytab['entries'] = []
            try:
                kt = krb5.Keytab(ctx, contents=keytab['keytab'])
                for i in kt.entries:
                    keytab['entries'].append({
                        'vno': i.vno,
                        'principal': i.principal,
                        'enctype': i.enctype
                    })
            except krb5.KrbException:
                pass

            del keytab['keytab']
            return keytab

        return q.query(
            self.datastore.query_stream('kerberos.keytabs', callback=extend),
            *(filter or []),
            stream=True,
            **(params or {})
        )


@accepts(h.ref('kerberos-realm'))
class KerberosRealmCreateTask(Task):
    def verify(self, realm):
        return ['system']

    def run(self, realm):
        id = self.datastore.insert('kerberos.realms', realm)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'kerberos')
        self.dispatcher.dispatch_event('kerberos.realm.changed', {
            'operation': 'create',
            'ids': [id]
        })
        return id


@accepts(str, h.ref('kerberos-realm'))
class KerberosRealmUpdateTask(Task):
    def verify(self, id, realm):
        return ['system']

    def run(self, id, updated_fields):
        realm = self.datastore.get_by_id('kerberos.realms', id)
        realm.update(updated_fields)
        self.datastore.update('kerberos.realms', id, realm)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'kerberos')
        self.dispatcher.dispatch_event('kerberos.realm.changed', {
            'operation': 'update',
            'ids': [id]
        })

        return id


@accepts(str)
class KerberosRealmDeleteTask(Task):
    def verify(self, id):
        return ['system']

    def run(self, id):
        self.datastore.delete('kerberos.realms', id)
        self.dispatcher.dispatch_event('kerberos.realm.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@accepts(h.all_of(
    h.ref('kerberos-keytab'),
    h.required('name', 'keytab')
))
class KerberosKeytabCreateTask(Task):
    def verify(self, keytab):
        return ['system']

    def run(self, keytab):
        if self.datastore.exists('kerberos.keytabs', ('name', '=', keytab['name'])):
            raise TaskException(errno.EEXIST, 'Keytab {0} already exists'.format(keytab['name']))

        id = self.datastore.insert('kerberos.keytabs', keytab)
        generate_keytab(self.datastore)
        self.dispatcher.dispatch_event('kerberos.keytab.changed', {
            'operation': 'create',
            'ids': [id]
        })
        return id


@accepts(str, h.all_of(
    h.ref('kerberos-keytab'),
    h.forbidden('keytab', 'entries')
))
class KerberosKeytabUpdateTask(Task):
    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        if not self.datastore.exists('kerberos.keytabs', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Keytab with ID {0} doesn\'t exist'.format(id))

        keytab = self.datastore.get_by_id('kerberos.keytabs', id)
        keytab.update(updated_fields)
        self.datastore.update('kerberos.keytabs', id, keytab)
        generate_keytab(self.datastore)
        self.dispatcher.dispatch_event('kerberos.keytab.changed', {
            'operation': 'update',
            'ids': [id]
        })


@accepts(str)
class KerberosKeytabDeleteTask(Task):
    def verify(self, id):
        return ['system']

    def run(self, id):
        if not self.datastore.exists('kerberos.keytabs', ('id', '=', id)):
            raise TaskException(errno.ENOENT, 'Keytab with ID {0} doesn\'t exist'.format(id))

        self.datastore.delete('kerberos.keytabs', id)
        generate_keytab(self.datastore)
        self.dispatcher.dispatch_event('kerberos.keytab.changed', {
            'operation': 'delete',
            'ids': [id]
        })


def generate_keytab(datastore):
    ctx = krb5.Context()
    sys_keytab = krb5.Keytab(ctx, name='FILE:/etc/krb5.keytab')
    sys_keytab.clear()
    for i in datastore.query_stream('kerberos.keytabs'):
        k = krb5.Keytab(ctx, contents=i['keytab'])
        for entry in k.entries:
            sys_keytab.add(entry)


def collect_debug(dispatcher):
    yield AttachFile('krb5.conf', '/etc/krb5.conf')
    yield AttachCommandOutput('klist', ['/usr/bin/klist', 'conf', 'list'])


def _init(dispatcher, plugin):
    plugin.register_schema_definition('kerberos-realm', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'realm': {'type': 'string'},
            'kdc_address': {'type': ['string', 'null']},
            'admin_server_address': {'type': ['string', 'null']},
            'password_server_address': {'type': ['string', 'null']}
        }
    })

    plugin.register_schema_definition('kerberos-keytab', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'name': {'type': 'string'},
            'keytab': {'type': 'binary'},
            'entries': {
                'type': 'array',
                'items': {'$ref': 'kerberos-keytab-entry'}
            }
        }
    })

    plugin.register_schema_definition('kerberos-keytab-entry', {
        'type': 'object',
        'properties': {
            'principal': {'type': 'string'},
            'enctype': {'type': 'string'},
            'vno': {'type': 'integer'}
        }
    })

    plugin.register_provider('kerberos.realm', KerberosRealmsProvider)
    plugin.register_provider('kerberos.keytab', KerberosKeytabsProvider)

    plugin.register_event_type('kerberos.realm.changed')
    plugin.register_task_handler('kerberos.realm.create', KerberosRealmCreateTask)
    plugin.register_task_handler('kerberos.realm.update', KerberosRealmUpdateTask)
    plugin.register_task_handler('kerberos.realm.delete', KerberosRealmDeleteTask)

    plugin.register_event_type('kerberos.keytab.changed')
    plugin.register_task_handler('kerberos.keytab.create', KerberosKeytabCreateTask)
    plugin.register_task_handler('kerberos.keytab.update', KerberosKeytabUpdateTask)
    plugin.register_task_handler('kerberos.keytab.delete', KerberosKeytabDeleteTask)

    generate_keytab(dispatcher.datastore)
