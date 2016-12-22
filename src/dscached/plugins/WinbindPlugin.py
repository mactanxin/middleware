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
import uuid
import krb5
import ldap3
import ldap3.utils.conv
import smbconf
import wbclient
import logging
import subprocess
import errno
import sid
import contextlib
from threading import Thread, Condition
from datetime import datetime
from plugin import DirectoryServicePlugin, DirectoryState, params, status
from utils import domain_to_dn, join_dn, obtain_or_renew_ticket, have_ticket, get_srv_records, get_a_records, LdapQueryBuilder
from freenas.dispatcher.rpc import SchemaHelper as h
from freenas.utils import normalize, first_or_default
from freenas.utils.query import get


AD_REALM_ID = uuid.UUID('01a35b82-0168-11e6-88d6-0cc47a3511b4')
WINBIND_ID_BASE = uuid.UUID('e6ae958e-fdaa-44a1-8905-0a0c8d015245')
WINBINDD_PIDFILE = '/var/run/samba4/winbindd.pid'
WINBINDD_KEEPALIVE = 60
AD_LDAP_ATTRIBUTE_MAPPING = {
    'id': 'objectGUID',
    'sd': 'objectSid',
    'username': 'sAMAccountName',
    'full_name': 'name',
    'builtin': True,
    'uid': None
}

logger = logging.getLogger(__name__)


def yesno(val):
    return 'yes' if val else 'no'


@params(h.ref('winbind-directory-params'))
@status(h.ref('winbind-directory-status'))
class WinbindPlugin(DirectoryServicePlugin):
    def __init__(self, context):
        self.context = context
        self.uid_min = 90000001
        self.uid_max = 100000000
        self.dc = None
        self.enabled = False
        self.domain_info = None
        self.domain_name = None
        self.parameters = None
        self.directory = None
        self.ldap_servers = None
        self.ldap = None
        self.domain_users_guid = None
        self.user_dn = None
        self.group_dn = None
        self.cv = Condition()
        self.bind_thread = Thread(target=self.bind, daemon=True)
        self.bind_thread.start()
        os.environ['LOGNAME'] = 'root'

        # Remove winbind cache files
        with contextlib.suppress(FileNotFoundError):
            os.remove('/var/db/samba4/winbindd_cache.tdb')

        with contextlib.suppress(FileNotFoundError):
            os.remove('/var/db/samba4/winbindd_cache.tdb.bak')

        with contextlib.suppress(FileNotFoundError):
            os.remove('/var/db/samba4/winbindd_cache.tdb.old')

    @property
    def realm(self):
        return self.parameters['realm']

    @property
    def base_dn(self):
        return domain_to_dn(self.realm)

    @property
    def wbc(self):
        return wbclient.Context()

    @property
    def principal(self):
        return '{0}@{1}'.format(self.parameters['username'], self.parameters['realm'].upper())

    @property
    def domain_users_sid(self):
        return '{0}-{1}'.format(self.domain_info.sid, 513)

    @property
    def ldap_addresses(self):
        records = get_srv_records('ldap', 'tcp', self.parameters['realm'], self.parameters.get('dc_address'))
        return [str(i) for i in records]

    @staticmethod
    def normalize_parameters(parameters):
        return normalize(parameters, {
            '%type': 'winbind-directory-params',
            'realm': '',
            'username': 'Administrator',
            'password': None,
            'krb_principal': None,
            'site_name': None,
            'dc_address': None,
            'gcs_address': None,
            'allow_dns_updates': True,
            'sasl_wrapping': 'PLAIN'
        })

    def is_joined(self, full=False):
        if full:
            # Check if we have ticket
            if not have_ticket(self.principal):
                logger.debug('Ticket not found or expired')
                return False

            # Check if we can fetch domain SID
            if subprocess.call(['/usr/local/bin/net', 'getdomainsid']) != 0:
                logger.debug('Cannot fetch domain SID')
                return False

        # Check if winbind is running
        if self.wbc.interface is None:
            logger.debug('Winbind client interface not available')
            return False

        return True

    def __renew_ticket(self):
        obtain_or_renew_ticket(self.principal, self.parameters['password'])

    def search(self, search_base, search_filter, attributes=None):
        if self.ldap.closed:
            self.ldap.bind()

        return self.ldap.extend.standard.paged_search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=ldap3.SUBTREE,
            attributes=attributes or ldap3.ALL_ATTRIBUTES,
            paged_size=16,
            generator=True
        )

    def search_one(self, *args, **kwargs):
        return first_or_default(None, self.search(*args, **kwargs))

    def bind(self):
        logger.debug('Bind thread: starting')
        while True:
            with self.cv:
                notify = self.cv.wait(60)

                if notify:
                    if self.is_joined() and self.enabled:
                        self.directory.put_state(DirectoryState.EXITING)
                        self.leave()

                if self.enabled:
                    try:
                        obtain_or_renew_ticket(self.principal, self.parameters['password'])
                    except krb5.KrbException as err:
                        self.directory.put_status(errno.ENXIO, '{0} <{1}>'.format(str(err), type(err).__name__))
                        self.directory.put_state(DirectoryState.FAILURE)
                        continue

                    if not self.is_joined(True):
                        # Try to rejoin
                        logger.debug('Keepalive thread: rejoining')
                        self.directory.put_state(DirectoryState.JOINING)
                        if not self.join():
                            continue
                    else:
                        self.domain_info = self.wbc.get_domain_info(self.realm)
                        self.domain_name = self.wbc.interface.netbios_domain

                    if self.directory.state != DirectoryState.BOUND:
                        try:
                            logger.debug('Initializing LDAP connection')
                            logger.debug('LDAP server addresses: {0}'.format(', '.join(self.ldap_addresses)))
                            ldap_addresses = self.ldap_addresses
                            sasl_credentials = None

                            if self.parameters.get('dc_address'):
                                logger.debug('Using manually configured DC address')
                                sasl_credentials = (self.ldap_addresses[0][:-1],)
                                ldap_addresses = get_a_records(self.ldap_addresses[0], self.parameters['dc_address'])

                            self.ldap_servers = [ldap3.Server(i) for i in ldap_addresses]
                            self.ldap = ldap3.Connection(
                                self.ldap_servers,
                                client_strategy='ASYNC',
                                authentication=ldap3.SASL,
                                sasl_mechanism='GSSAPI',
                                sasl_credentials=sasl_credentials
                            )

                            if not self.ldap.bind():
                                # try TLS now
                                logger.warning('Regular bind failed, trying STARTTLS...')
                                self.ldap.start_tls()
                                if not self.ldap.bind():
                                    raise RuntimeError("Failed to bind")

                            logger.debug('LDAP bound')

                            # Figure out group DN and prefetch "Domain Users" GUID
                            for dn in ('CN=Users', 'CN=Groups'):
                                du = self.search_one(join_dn(dn, self.base_dn), '(sAMAccountName=Domain Users)')
                                if not du:
                                    continue

                                self.domain_users_guid = uuid.UUID(bytes=du['attributes']['objectGUID'][0])
                                self.user_dn = join_dn('CN=Users', self.base_dn)
                                self.group_dn = join_dn(dn, self.base_dn)
                                logger.debug('Group DN is {0}'.format(self.group_dn))
                                logger.debug('Domain Users GUID is {0}'.format(self.domain_users_guid))
                                break
                            else:
                                raise RuntimeError('Failed to fetch Domain Users')

                        except BaseException as err:
                            self.directory.put_status(errno.ENXIO, '{0} <{1}>'.format(str(err), type(err).__name__))
                            self.directory.put_state(DirectoryState.FAILURE)
                        else:
                            self.directory.put_state(DirectoryState.BOUND)
                else:
                    if self.directory.state != DirectoryState.DISABLED:
                        self.leave()
                        self.directory.put_state(DirectoryState.DISABLED)

    def configure_smb(self, enable):
        workgroup = self.parameters['realm'].split('.')[0]
        cfg = smbconf.SambaConfig('registry')
        params = {
            'server role': 'member server',
            'local master': 'no',
            'domain master': 'no',
            'preferred master': 'no',
            'domain logons': 'no',
            'workgroup': workgroup,
            'realm': self.parameters['realm'],
            'security': 'ads',
            'winbind cache time': str(self.context.cache_ttl),
            'winbind offline logon': 'yes',
            'winbind enum users': 'no',
            'winbind enum groups': 'no',
            'winbind nested groups': 'yes',
            'winbind use default domain': 'no',
            'winbind refresh tickets': 'no',
            'idmap config *: backend': 'tdb',
            'idmap config *: range': '0-65536',
            'idmap config {0}: backend'.format(workgroup): 'rid',
            'idmap config {0}: range'.format(workgroup):
                '{0}-{1}'.format(self.uid_min, self.uid_max),
            'client use spnego': 'yes',
            'allow trusted domains': 'no',
            'client ldap sasl wrapping': self.parameters['sasl_wrapping'].lower(),
            'template shell': '/bin/sh',
            'template homedir': '/home/%U'
        }

        if enable:
            for k, v in params.items():
                logger.debug('Setting samba parameter "{0}" to "{1}"'.format(k, v))
                cfg[k] = v
        else:
            for k in params:
                del cfg[k]

            params = {
                'server role': 'auto',
                'workgroup': self.context.configstore.get('service.smb.workgroup'),
                'local master': yesno(self.context.configstore.get('service.smb.local_master'))
            }

            for k, v in params.items():
                logger.debug('Setting samba parameter "{0}" to "{1}"'.format(k, v))
                cfg[k] = v

        self.context.client.call_sync('service.restart', 'smb')

    def get_directory_info(self):
        return {
            'domain_name': self.domain_name,
            'domain_controller': self.dc
        }

    def convert_user(self, entry):
        if not entry:
            return

        entry = dict(entry['attributes'])
        if 'user' not in get(entry, 'objectClass'):
            # not a user
            return

        username = get(entry, 'sAMAccountName.0')
        usersid = sid.sid(get(entry, 'objectSid.0'), sid.SID_BINARY)
        groups = []
        wbu = self.wbc.get_user(name='{0}\\{1}'.format(self.realm, username))

        if not wbu:
            logging.warning('User {0} found in LDAP, but not in winbindd.'.format(username))
            return

        if get(entry, 'memberOf'):
            builder = LdapQueryBuilder()
            qstr = builder.build_query([
                ('distinguishedName', 'in', get(entry, 'memberOf'))
            ])

            for r in self.search(self.group_dn, qstr):
                r = dict(r['attributes'])
                guid = uuid.UUID(bytes=get(r, 'objectGUID.0'))
                groups.append(str(guid))

        return {
            'id': str(uuid.UUID(bytes=get(entry, 'objectGUID.0'))),
            'sid': str(usersid),
            'uid': wbu.passwd.pw_uid,
            'builtin': False,
            'username': username,
            'aliases': [wbu.passwd.pw_name],
            'full_name': get(entry, 'name.0'),
            'email': None,
            'locked': False,
            'sudo': False,
            'password_disabled': False,
            'group': str(self.domain_users_guid),
            'groups': groups,
            'shell': wbu.passwd.pw_shell,
            'home': wbu.passwd.pw_dir
        }

    def convert_group(self, entry):
        if not entry:
            return

        entry = dict(entry['attributes'])
        if 'group' not in get(entry, 'objectClass'):
            # not a group
            return

        groupname = get(entry, 'sAMAccountName.0')
        groupsid = sid.sid(get(entry, 'objectSid.0'), sid.SID_BINARY)
        parents = []
        wbg = self.wbc.get_group(name='{0}\\{1}'.format(self.realm, groupname))

        if not wbg:
            logging.warning('Group {0} found in LDAP, but not in winbindd.'.format(groupname))
            return

        if get(entry, 'memberOf'):
            builder = LdapQueryBuilder()
            qstr = builder.build_query([
                ('distinguishedName', 'in', get(entry, 'memberOf'))
            ])

            for r in self.search(self.group_dn, qstr):
                r = dict(r['attributes'])
                guid = uuid.UUID(bytes=get(r, 'objectGUID.0'))
                parents.append(str(guid))

        return {
            'id': str(uuid.UUID(bytes=get(entry, 'objectGUID.0'))),
            'sid': str(groupsid),
            'gid': wbg.group.gr_gid,
            'builtin': False,
            'name': groupname,
            'aliases': [wbg.group.gr_name],
            'parents': parents,
            'sudo': False
        }

    def getpwent(self, filter=None, params=None):
        logger.debug('getpwent(filter={0}, params={1})'.format(filter, params))
        if not self.is_joined():
            logger.debug('getpwent: not joined')
            return []

        query = LdapQueryBuilder(AD_LDAP_ATTRIBUTE_MAPPING)
        qstr = query.build_query([['objectClass', '=', 'person']] + (filter or []))
        logger.debug('getpwent query string: {0}'.format(qstr))
        results = self.search(self.user_dn, qstr)
        return (self.convert_user(i) for i in results)

    def getpwuid(self, uid):
        logger.debug('getpwuid(uid={0})'.format(uid))
        if not (self.uid_min <= uid <= self.uid_max):
            return

        if not self.is_joined():
            logger.debug('getpwuid: not joined')
            return

        wbu = self.wbc.get_user(uid=uid)
        if not wbu:
            return

        usid = ldap3.utils.conv.escape_bytes(bytes(wbu.sid))
        return self.convert_user(self.search_one(self.user_dn, '(objectSid={0})'.format(usid)))

    def getpwuuid(self, id):
        logger.debug('getpwuuid(uuid={0})'.format(id))
        if not self.is_joined():
            logger.debug('getpwuuid: not joined')
            return

        guid = ldap3.utils.conv.escape_bytes(uuid.UUID(id).bytes)
        return self.convert_user(self.search_one(self.user_dn, '(objectGUID={0})'.format(guid)))

    def getpwnam(self, name):
        logger.debug('getpwnam(name={0})'.format(name))

        if '\\' in name:
            domain, name = name.split('\\', 1)
            if domain != self.domain_name:
                return

        if not self.is_joined():
            logger.debug('getpwnam: not joined')
            return

        return self.convert_user(self.search_one(self.user_dn, '(sAMAccountName={0})'.format(name)))

    def getgrent(self, filter=None, params=None):
        logger.debug('getgrent(filter={0}, params={1})'.format(filter, params))
        if not self.is_joined():
            logger.debug('getgrent: not joined')
            return []

        results = self.search(self.group_dn, '(objectClass=group)')
        return (self.convert_group(i) for i in results)

    def getgrnam(self, name):
        logger.debug('getgrnam(name={0})'.format(name))

        if '\\' in name:
            domain, name = name.split('\\', 1)
            if domain != self.domain_name:
                return

        if not self.is_joined():
            logger.debug('getgrnam: not joined')
            return

        return self.convert_group(self.search_one(self.group_dn, '(sAMAccountName={0})'.format(name)))

    def getgruuid(self, id):
        logger.debug('getgruuid(uuid={0})'.format(id))
        if not self.is_joined():
            logger.debug('getgruuid: not joined')
            return

        guid = ldap3.utils.conv.escape_bytes(uuid.UUID(id).bytes)
        return self.convert_group(self.search_one(self.group_dn, '(objectGUID={0})'.format(guid)))

    def getgrgid(self, gid):
        logger.debug('getgrgid(gid={0})'.format(gid))
        if not self.is_joined():
            logger.debug('getgrgid: not joined')
            return

        wbg = self.wbc.get_group(gid=gid)
        if not wbg:
            return

        usid = ldap3.utils.conv.escape_bytes(bytes(wbg.sid))
        return self.convert_group(self.search_one(self.group_dn, '(objectSid={0})'.format(usid)))

    def configure(self, enable, directory):
        with self.cv:
            self.enabled = enable
            self.directory = directory
            self.parameters = directory.parameters
            if directory.min_uid:
                self.uid_min = directory.min_uid
                self.uid_max = directory.max_uid

            self.cv.notify_all()

        return self.realm.lower()

    def join(self):
        logger.info('Trying to join to {0}...'.format(self.realm))

        try:
            self.configure_smb(True)
            obtain_or_renew_ticket(self.principal, self.parameters['password'])

            try:
                subprocess.check_output(['/usr/local/bin/net', 'ads', 'join', self.realm, '-k'])
                self.context.client.call_sync('service.restart', 'smb')
            except subprocess.CalledProcessError as err:
                # Undo possibly partially successful join
                subprocess.call(['/usr/local/bin/net', 'ads', 'leave'])
                raise RuntimeError(err.output.decode('utf-8'))

            self.dc = self.wbc.ping_dc(self.realm)
            self.domain_info = self.wbc.get_domain_info(self.realm)
            self.domain_name = self.wbc.interface.netbios_domain

        except BaseException as err:
            self.directory.put_status(errno.ENXIO, str(err))
            self.directory.put_state(DirectoryState.FAILURE)
            return False

        logger.info('Sucessfully joined to the domain {0}'.format(self.realm))
        return True

    def leave(self):
        logger.info('Leaving domain')
        subprocess.call(['/usr/local/bin/net', 'ads', 'leave'])
        self.configure_smb(False)
        self.dc = None
        self.domain_name = None
        self.domain_info = None
        self.ldap = None

    def get_kerberos_realm(self, parameters):
        ret = {
            'id': AD_REALM_ID,
            'realm': parameters['realm'].upper(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }

        if parameters.get('dc_address'):
            ret['kdc_address'] = parameters['dc_address']

        return ret


def _init(context):
    context.register_plugin('winbind', WinbindPlugin)

    context.register_schema('winbind-directory-params-sasl-wrapping', {
        'type': 'string',
        'enum': ['PLAIN', 'SIGN', 'SEAL']
    })

    context.register_schema('winbind-directory-params', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['winbind-directory-params']},
            'realm': {'type': 'string'},
            'username': {'type': ['string', 'null']},
            'password': {'type': ['string', 'null']},
            'krb_principal': {'type': ['string', 'null']},
            'site_name': {'type': ['string', 'null']},
            'dc_address': {'type': ['string', 'null']},
            'gcs_address': {'type': ['string', 'null']},
            'allow_dns_updates': {'type': 'boolean'},
            'sasl_wrapping': {'$ref': 'winbind-directory-params-sasl-wrapping'}
        }
    })

    context.register_schema('winbind-directory-status', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'type': {'enum': ['winbind-directory-status']},
            'joined': {'type': 'boolean'},
            'domain_controller': {'type': 'string'},
            'server_time': {'type': 'datetime'}
        }
    })
