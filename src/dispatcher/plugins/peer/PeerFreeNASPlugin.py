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

import io
import time
import socket
import errno
import logging
import gevent
import random
import copy
from datetime import datetime, timedelta
from freenas.dispatcher.client import Client
from paramiko import AuthenticationException, RSAKey
from utils import get_freenas_peer_client, call_task_and_check_state
from freenas.utils import exclude, query as q, first_or_default
from freenas.utils.password import unpassword
from freenas.utils.decorators import limit
from freenas.utils.url import wrap_address, is_ip
from freenas.utils.lazy import lazy
from freenas.dispatcher.rpc import (
    RpcException, SchemaHelper as h, description, accepts, returns, private, generator, unauthenticated
)
from task import Task, Provider, TaskException, TaskWarning, VerifyException, query, TaskDescription


logger = logging.getLogger(__name__)

auth_code_lifetime = None

ssh_port = None
hostname = None
auth_codes = []

temp_pubkeys = []


@description('Provides information about known FreeNAS peers')
class PeerFreeNASProvider(Provider):
    @query('Peer')
    @generator
    def query(self, filter=None, params=None):
        def extend_query():
            for i in self.datastore.query_stream('peers', ('type', '=', 'freenas')):
                i['status'] = lazy(self.get_status, i['id'])
                yield i

        return q.query(
            extend_query(),
            *(filter or []),
            stream=True,
            **(params or {})
        )

    @private
    @accepts(str)
    @returns(h.ref('PeerStatus'))
    def get_status(self, id):
        peer = self.dispatcher.call_sync('peer.query', [('id', '=', id), ('type', '=', 'freenas')], {'single': True})
        if not peer:
            return id, {'state': 'UNKNOWN', 'rtt': None}

        credentials = peer['credentials']

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            start_time = datetime.utcnow()
            s.connect((credentials['address'], credentials['port']))
            delta = datetime.utcnow() - start_time
            return {'state': 'ONLINE', 'rtt': delta.total_seconds()}
        except socket.error:
            return {'state': 'OFFLINE', 'rtt': None}
        finally:
            s.close()

    @private
    def get_ssh_keys(self):
        try:
            with open('/etc/ssh/ssh_host_rsa_key.pub') as f:
                return f.read(), self.configstore.get('peer.freenas.key.public')
        except FileNotFoundError:
            raise RpcException(errno.ENOENT, 'Hostkey file not found')

    def create_auth_code(self):
        while True:
            code = random.randint(100000, 999999)
            if code not in auth_codes:
                break

        auth_codes.append({
            'code': code,
            'expires_at': datetime.utcnow() + timedelta(seconds=auth_code_lifetime)
        })
        gevent.spawn(cycle_code_lifetime, code)
        return code

    @unauthenticated
    def auth_with_code(self, code, address, port=22):
        try:
            if auth_with_code(code):
                self.dispatcher.submit_task('peer.freenas.create', {
                    'type': 'freenas',
                    'credentials': {
                        '%type': 'FreenasCredentials',
                        'address': address,
                        'port': port
                    }
                }, {
                    'key_auth': True
                })
                hostid = self.dispatcher.call_sync('system.info.host_uuid')
                hostkey, pubkey = self.get_ssh_keys()
                return hostid, pubkey
            else:
                raise RpcException(errno.EAUTH, 'Authentication code {0} is not valid'.format(code))
        except RuntimeError as err:
            raise RpcException(errno.EACCES, err)

    def void_auth_codes(self):
        auth_codes.clear()

    def invalidate_code(self, code):
        minimal_match = lambda k: k['expires_at'] == code['expires_at'] and k['code'].startswith(code['code'][:2])
        code_match = lambda k: str(k['code']).startswith(str(code)[:str(code).find('*')])
        m_funct = minimal_match

        if not isinstance(code_match, (str, int)):
            m_funct = code_match

        match = first_or_default(
            m_funct,
            auth_codes
        )
        if match:
            invalidate_code(match['code'])

    @generator
    def get_auth_codes(self):
        current_codes = copy.deepcopy(auth_codes)
        for code in current_codes:
            code['code'] = str(code['code'])[:-4] + '****'
            yield code

    @private
    def put_temp_pubkey(self, key):
        temp_pubkeys.append(key)

    @private
    @generator
    def get_temp_pubkeys(self):
        for k in temp_pubkeys:
            yield k

    @private
    def remove_temp_pubkey(self, key):
        try:
            temp_pubkeys.remove(key)
        except ValueError:
            pass


@description('Exchanges SSH keys with remote FreeNAS machine')
@accepts(h.all_of(
    h.ref('Peer'),
    h.required('type', 'credentials'),
    h.forbidden('name')
))
class FreeNASPeerCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Exchanging SSH keys with remote host'

    def describe(self, peer, initial_credentials):
        return TaskDescription('Exchanging SSH keys with the remote {name}', name=q.get(peer, 'credentials.address', ''))

    def verify(self, peer, initial_credentials):
        credentials = peer['credentials']
        remote = credentials.get('address')
        if not initial_credentials:
            raise VerifyException(
                errno.EINVAL,
                'No credentials provided. Provide either username and password or token'
            )

        username = initial_credentials.get('username')
        password = initial_credentials.get('password')

        if not remote:
            raise VerifyException(errno.EINVAL, 'Address of remote host has to be specified')

        if not initial_credentials.get('auth_code') and not initial_credentials.get('key_auth'):
            if not username:
                raise VerifyException(errno.EINVAL, 'Username has to be specified')

            if not password:
                raise VerifyException(errno.EINVAL, 'Password has to be specified')

        return ['system']

    def run(self, peer, initial_credentials):
        hostid = self.dispatcher.call_sync('system.info.host_uuid')
        hostname = self.dispatcher.call_sync('system.general.get_config')['hostname']
        remote_peer_name = hostname
        credentials = peer['credentials']
        remote = credentials.get('address')
        port = credentials.get('port', 22)
        username = initial_credentials.get('username')
        password = initial_credentials.get('password')
        auth_code = initial_credentials.get('auth_code')
        key_auth = initial_credentials.get('key_auth')

        local_ssh_config = self.dispatcher.call_sync('service.sshd.get_config')

        if self.datastore.exists('peers', ('credentials.address', '=', remote), ('type', '=', 'freenas')):
            raise TaskException(
                errno.EEXIST,
                'FreeNAS peer entry for {0} already exists'.format(remote)
            )

        remote_client = Client()

        try:
            if auth_code:
                try:
                    remote_client.connect('ws://{0}'.format(wrap_address(remote)))
                except (AuthenticationException, OSError, ConnectionRefusedError):
                    raise TaskException(errno.ECONNABORTED, 'Cannot connect to {0}:{1}'.format(remote, port))

                try:
                    remote_host_uuid, pubkey = remote_client.call_sync(
                        'peer.freenas.auth_with_code',
                        auth_code,
                        hostname,
                        local_ssh_config['port']
                    )
                except RpcException as err:
                    raise TaskException(err.code, err.message)

                try:
                    self.dispatcher.call_sync('peer.freenas.put_temp_pubkey', pubkey)
                    if not self.dispatcher.test_or_wait_for_event(
                        'peer.changed',
                        lambda ar: ar['operation'] == 'create' and remote_host_uuid in ar['ids'],
                        lambda: self.datastore.exists('peers', ('id', '=', remote_host_uuid)),
                        timeout=30
                    ):
                        raise TaskException(
                            errno.EAUTH,
                            'FreeNAS peer creation failed. Check connection to host {0}.'.format(remote)
                        )
                finally:
                    self.dispatcher.call_sync('peer.freenas.remove_temp_pubkey', pubkey)

            else:
                try:
                    if key_auth:
                        with io.StringIO() as f:
                            f.write(self.configstore.get('peer.freenas.key.private'))
                            f.seek(0)
                            pkey = RSAKey.from_private_key(f)

                        max_tries = 50
                        while True:
                            try:
                                remote_client.connect('ws+ssh://freenas@{0}'.format(
                                    wrap_address(remote)), pkey=pkey, port=port
                                )
                                break
                            except AuthenticationException:
                                if max_tries:
                                    max_tries -= 1
                                    time.sleep(1)
                                else:
                                    raise
                    else:
                        remote_client.connect(
                            'ws+ssh://{0}@{1}'.format(username, wrap_address(remote)),
                            port=port,
                            password=unpassword(password)
                        )

                    remote_client.login_service('replicator')
                except (AuthenticationException, OSError, ConnectionRefusedError):
                    raise TaskException(errno.ECONNABORTED, 'Cannot connect to {0}:{1}'.format(remote, port))

                local_host_key, local_pub_key = self.dispatcher.call_sync('peer.freenas.get_ssh_keys')
                remote_host_key, remote_pub_key = remote_client.call_sync('peer.freenas.get_ssh_keys')
                ip_at_remote_side = remote_client.local_address[0]

                remote_hostname = remote_client.call_sync('system.general.get_config')['hostname']

                remote_host_key = remote_host_key.rsplit(' ', 1)[0]
                local_host_key = local_host_key.rsplit(' ', 1)[0]

                if remote_client.call_sync('peer.query', [('id', '=', hostid)]):
                    raise TaskException(errno.EEXIST, 'Peer entry of {0} already exists at {1}'.format(hostname, remote))

                peer['credentials'] = {
                    '%type': 'FreenasCredentials',
                    'pubkey': remote_pub_key,
                    'hostkey': remote_host_key,
                    'port': port,
                    'address': remote_hostname
                }

                local_id = remote_client.call_sync('system.info.host_uuid')
                peer['id'] = local_id
                peer['name'] = remote_hostname
                ip = socket.gethostbyname(remote)

                created_id = self.run_subtask_sync(
                    'peer.freenas.create_local',
                    peer,
                    ip,
                    True
                )

                peer['id'] = hostid
                peer['name'] = remote_peer_name
                peer['credentials'] = {
                    '%type': 'FreenasCredentials',
                    'pubkey': local_pub_key,
                    'hostkey': local_host_key,
                    'port': local_ssh_config['port'],
                    'address': hostname
                }

                try:
                    call_task_and_check_state(
                        remote_client,
                        'peer.freenas.create_local',
                        peer,
                        ip_at_remote_side
                    )
                except TaskException:
                    self.datastore.delete('peers', local_id)
                    self.dispatcher.dispatch_event('peer.changed', {
                        'operation': 'delete',
                        'ids': [local_id]
                    })
                    raise

                return created_id
        finally:
            remote_client.disconnect()


@private
@description('Creates FreeNAS peer entry in database')
@accepts(h.ref('Peer'), str, bool)
class FreeNASPeerCreateLocalTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Creating FreeNAS peer entry'

    def describe(self, peer, ip, local=False):
        return TaskDescription('Creating FreeNAS peer entry {name}', name=peer['name'])

    def verify(self, peer, ip, local=False):
        return []

    def run(self, peer, ip, local=False):
        def ping(address, port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((address, port))
            finally:
                s.close()

        if self.datastore.exists('peers', ('id', '=', peer['id'])):
            raise TaskException(errno.EEXIST, 'FreeNAS peer entry {0} already exists'.format(peer['name']))

        if self.datastore.exists('peers', ('name', '=', peer['name'])):
            raise TaskException(errno.EINVAL, 'Peer entry {0} already exists'.format(peer['name']))

        credentials = peer['credentials']

        try:
            ping(credentials['address'], credentials['port'])
        except socket.error:
            try:
                ping(ip, credentials['port'])
                credentials['address'] = ip
            except socket.error as err:
                raise TaskException(err.errno, '{0} is not reachable. Check connection'.format(credentials['address']))

        if ip and not is_ip(ip) and socket.gethostbyname(credentials['address']) != socket.gethostbyname(ip):
            raise TaskException(
                errno.EINVAL,
                'Resolved peer {0} IP {1} does not match desired peer IP {2}'.format(
                    credentials['address'],
                    socket.gethostbyname(credentials['address']),
                    ip
                )
            )

        id = self.datastore.insert('peers', peer)
        if not local:
            self.dispatcher.dispatch_event('peer.changed', {
                'operation': 'create',
                'ids': [id]
            })

        return id


@description('Removes FreeNAS peer entry')
@accepts(str)
class FreeNASPeerDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Removing FreeNAS peer entry'

    def describe(self, id):
        peer = self.datastore.get_by_id('peers', id)
        return TaskDescription('Removing FreeNAS peer entry: {name}', name=peer['name'])

    def verify(self, id):
        return ['system']

    def run(self, id):
        peer = self.datastore.get_by_id('peers', id)
        if not peer:
            raise TaskException(errno.ENOENT, 'Peer entry {0} does not exist'.format(id))

        remote = q.get(peer, 'credentials.address')
        remote_client = None
        hostid = self.dispatcher.call_sync('system.info.host_uuid')
        try:
            try:
                remote_client = get_freenas_peer_client(self, remote)

                call_task_and_check_state(
                    remote_client,
                    'peer.freenas.delete_local',
                    hostid,
                    False
                )
            except RpcException as e:
                self.add_warning(TaskWarning(
                    e.code,
                    'Remote {0} is unreachable. Delete operation is performed at local side only.'.format(remote)
                ))
            except ValueError as e:
                self.add_warning(TaskWarning(
                    errno.EINVAL,
                    str(e)
                ))

            self.run_subtask_sync(
                'peer.freenas.delete_local',
                id,
                True
            )

        finally:
            if remote_client:
                remote_client.disconnect()


@private
@description('Removes local FreeNAS peer entry from database')
@accepts(str, bool)
class FreeNASPeerDeleteLocalTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Removing FreeNAS peer entry'

    def describe(self, id, local=False):
        peer = self.datastore.get_by_id('peers', id)
        return TaskDescription('Removing FreeNAS peer entry {name}', name=peer['name'])

    def verify(self, id, local=False):
        return ['system']

    def run(self, id, local=False):
        peer = self.datastore.get_by_id('peers', id)
        if not peer:
            raise TaskException(errno.ENOENT, 'FreeNAS peer entry {0} does not exist'.format(peer['name']))
        self.datastore.delete('peers', id)
        if not local:
            self.dispatcher.dispatch_event('peer.changed', {
                'operation': 'delete',
                'ids': [id]
            })


@private
@description('Updates FreeNAS peer entry in database')
@accepts(str, h.ref('Peer'))
class FreeNASPeerUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating FreeNAS peer entry'

    def describe(self, id, updated_fields):
        peer = self.datastore.get_by_id('peers', id)
        return TaskDescription('Updating FreeNAS peer entry {name}', name=peer['name'])

    def verify(self, id, updated_fields):
        return ['system']

    def run(self, id, updated_fields):
        peer = self.datastore.get_by_id('peers', id)
        if not peer:
            raise TaskException(errno.ENOENT, 'FreeNAS peer entry {0} does not exist'.format(id))

        if 'name' in updated_fields:
            raise TaskException(errno.EINVAL, 'Name of FreeNAS peer cannot be updated')

        if 'type' in updated_fields:
            raise TaskException(errno.EINVAL, 'Type of FreeNAS peer cannot be updated')

        if 'id' in updated_fields:
            raise TaskException(errno.EINVAL, 'ID of FreeNAS peer cannot be updated')

        peer.update(updated_fields)

        self.datastore.update('peers', id, peer)


@private
@description('Updates remote FreeNAS peer entry')
@accepts(str)
class FreeNASPeerUpdateRemoteTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating remote FreeNAS peer'

    def describe(self, id):
        peer = self.datastore.get_by_id('peers', id)
        return TaskDescription('Updating remote FreeNAS peer {name}', name=peer['name'])

    def verify(self, id):
        return ['system']

    def run(self, id):
        peer = self.datastore.get_by_id('peers', id)
        hostid = self.dispatcher.call_sync('system.info.host_uuid')
        remote_client = None
        if not peer:
            raise TaskException(errno.ENOENT, 'FreeNAS peer entry {0} does not exist'.format(id))

        try:
            remote_client = get_freenas_peer_client(self, peer['credentials']['address'])
            remote_peer = remote_client.call_sync('peer.query', [('id', '=', hostid)], {'single': True})
            if not remote_peer:
                raise TaskException(errno.ENOENT, 'Remote side of peer {0} does not exist'.format(peer['name']))

            ip_at_remote_side = remote_client.local_address[0]
            hostname = self.dispatcher.call_sync('system.general.get_config')['hostname']
            port = self.dispatcher.call_sync('service.sshd.get_config')['port']

            remote_peer['name'] = hostname

            remote_peer['credentials']['port'] = port
            remote_peer['credentials']['address'] = hostname

            call_task_and_check_state(
                remote_client,
                'peer.freenas.delete_local',
                hostid
            )

            remote_peer = exclude(remote_peer, 'created_at', 'updated_at')

            call_task_and_check_state(
                remote_client,
                'peer.freenas.create_local',
                remote_peer,
                ip_at_remote_side
            )
        finally:
            if remote_client:
                remote_client.disconnect()


def cycle_code_lifetime(code):
    gevent.sleep(auth_code_lifetime)
    invalidate_code(code)


@limit(limit=300, hours=1)
def auth_with_code(code):
    code_data = first_or_default(lambda c: c['code'] == code, auth_codes)
    if code_data:
        invalidate_code(code)
        return True
    else:
        return False


def invalidate_code(code):
    code_data = first_or_default(lambda c: c['code'] == code, auth_codes)
    if code_data:
        try:
            auth_codes.remove(code_data)
        except ValueError:
            pass


def _depends():
    return ['PeerPlugin', 'SSHPlugin', 'SystemInfoPlugin']


def _metadata():
    return {
        'type': 'peering',
        'subtype': 'freenas',
        'initial_credentials': True
    }


def _init(dispatcher, plugin):
    global ssh_port
    global hostname
    global auth_code_lifetime
    ssh_port = dispatcher.call_sync('service.sshd.get_config')['port']
    hostname = dispatcher.call_sync('system.general.get_config')['hostname']
    auth_code_lifetime = dispatcher.configstore.get('peer.freenas.token_lifetime')

    # Register schemas
    plugin.register_schema_definition('FreenasCredentials', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['FreenasCredentials']},
            'address': {'type': 'string'},
            'port': {'type': 'number'},
            'pubkey': {'type': 'string'},
            'hostkey': {'type': 'string'}
        },
        'additionalProperties': False
    })

    # Register schemas
    plugin.register_schema_definition('FreenasInitialCredentials', {
        'type': 'object',
        'properties': {
            '%type': {'enum': ['FreenasInitialCredentials']},
            'username': {'type': ['string', 'null']},
            'password': {'type': ['password', 'null']},
            'auth_code': {'type': ['integer', 'null']},
            'key_auth': {'type': 'boolean'}
        },
        'additionalProperties': False
    })

    # Register providers
    plugin.register_provider('peer.freenas', PeerFreeNASProvider)

    # Register tasks
    plugin.register_task_handler("peer.freenas.create", FreeNASPeerCreateTask)
    plugin.register_task_handler("peer.freenas.create_local", FreeNASPeerCreateLocalTask)
    plugin.register_task_handler("peer.freenas.delete", FreeNASPeerDeleteTask)
    plugin.register_task_handler("peer.freenas.delete_local", FreeNASPeerDeleteLocalTask)
    plugin.register_task_handler("peer.freenas.update", FreeNASPeerUpdateTask)
    plugin.register_task_handler("peer.freenas.update_remote", FreeNASPeerUpdateRemoteTask)

    # Event handlers methods
    def on_connection_change(args):
        global ssh_port
        global hostname
        new_ssh_port = dispatcher.call_sync('service.sshd.get_config')['port']
        new_hostname = dispatcher.call_sync('system.general.get_config')['hostname']
        if ssh_port != new_ssh_port or hostname != new_hostname:
            logger.debug('Address or SSH port has been updated. Populating change to FreeNAS peers')
            ssh_port = new_ssh_port
            hostname = new_hostname
            ids = dispatcher.call_sync('peer.freenas.query', {'select': 'id'})
            try:
                for id in ids:
                    dispatcher.call_task_sync('peer.freenas.update_remote', id)
            except RpcException:
                pass

    # Register event handlers
    plugin.register_event_handler('service.sshd.changed', on_connection_change)
    plugin.register_event_handler('system.general.changed', on_connection_change)

    # Generate freenas key pair on first run
    if not dispatcher.configstore.get('peer.freenas.key.private') or not dispatcher.configstore.get('peer.freenas.key.public'):
        key = RSAKey.generate(bits=2048)
        buffer = io.StringIO()
        key.write_private_key(buffer)
        dispatcher.configstore.set('peer.freenas.key.private', buffer.getvalue())
        dispatcher.configstore.set('peer.freenas.key.public', key.get_base64())
