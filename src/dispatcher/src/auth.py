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

import string
import random
import gevent
import logging
from freenas.dispatcher.rpc import RpcException
from lib.freebsd import sockstat

logger = logging.getLogger('dispatcher.auth')


class User(object):
    def __init__(self):
        self.uid = None
        self.name = None
        self.pwcheck = None
        self.token = None
        self.groups = []

    def check_password(self, password):
        return self.pwcheck(self.name, password)

    def check_local(self, client_addr, client_port, server_port):
        client = '{0}:{1}'.format(client_addr, client_port)
        for sock in sockstat(True, [server_port]):
            if sock['local'] == client:
                return True

        return False

    def has_role(self, role):
        return role in self.groups


class Service(object):
    def __init__(self):
        self.name = None

    def has_role(self, role):
        return True


class PasswordAuthenticator(object):
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.users = {}

    def get_user(self, name):
        try:
            entity = self.dispatcher.call_sync('dscached.account.getpwnam', name)
        except RpcException as err:
            logger.warning('Cannot look up user {0}: {1}'.format(name, str(err)))
            self.users.pop(name, None)
            return None

        def pwcheck(name, password):
            return self.dispatcher.call_sync('dscached.account.authenticate', name, password)

        user = User()
        user.uid = entity['uid']
        user.name = entity['username']
        user.pwcheck = pwcheck

        for id in entity['groups'] + [entity['group']]:
            grp = self.dispatcher.call_sync('dscached.group.getgruuid', id)
            if not grp:
                continue
            user.groups.append(grp['name'])

        self.users[user.name] = user
        return user

    def get_service(self, name):
        service = Service()
        service.name = name
        return service

    def invalidate_user(self, name):
        self.get_user(name)

    def flush_users(self, name):
        self.users.clear()


class TokenException(RuntimeError):
    pass


class Token(object):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        self.session_id = kwargs.pop('session_id', None)
        self.lifetime = kwargs.pop('lifetime')
        self.revocation_function = None
        # The below is a function handler that can be passed to the Token
        # to be executed whilst revocation of the token. Token is revoked
        # at the end of its lifetime. It takes only one argument as of now,
        # it being the reason for revocation. This fucntion is optional and
        # if not speficied then defaults to this class's "revoke_token" method.
        if 'revocation_function' in kwargs:
            self.revocation_function = kwargs.pop('revocation_function')

        self.revocation_reason = 'Logged out due to inactivity period'


class ShellToken(Token):
    def __init__(self, *args, **kwargs):
        super(ShellToken, self).__init__(*args, **kwargs)
        self.shell = kwargs.pop('shell')
        self.width = kwargs.pop('width')
        self.height = kwargs.pop('height')
        self.resize = None


class FileToken(Token):
    def file_token_revocation(self, token_store, token, token_id):
        # Try to close the file if its still open
        try:
            self.file.close()
        except:
            pass
        # Revoke the token
        logger.debug('Revoking FileToken for Reason: {0}'.format(self.revocation_reason))
        token_store.revoke_token(token_id)

    def __init__(self, *args, **kwargs):
        super(FileToken, self).__init__(*args, **kwargs)
        self.direction = kwargs.pop('direction')
        self.file = kwargs.pop('file')
        self.name = kwargs.pop('name')
        self.size = kwargs.pop('size', None)
        self.revocation_reason = '{0} of file: {1} timed out'.format(
            self.direction or 'Transfer',
            self.name or 'Unknown'
        )

        # Add a default token lifetime of 60 seconds for all FileToken
        # We do not want such tokens and their correspnding file handles
        # open indefinitely
        if self.lifetime is None:
            self.lifetime = 60
        self.revocation_function = self.file_token_revocation


class TokenStore(object):
    def __init__(self, dispatcher):
        self.dispatcher = dispatcher
        self.tokens = {}

    def generate_id(self):
        return ''.join([random.choice(string.ascii_letters + string.digits) for n in range(32)])

    def issue_token(self, token):
        token_id = self.generate_id()
        self.tokens[token_id] = token

        if token.lifetime:
            if token.revocation_function is not None:
                token.timer = gevent.spawn_later(
                    token.lifetime,
                    token.revocation_function,
                    self,
                    token,
                    token_id
                )
            else:
                token.timer = gevent.spawn_later(
                    token.lifetime,
                    self.revoke_token,
                    token_id
                )

        return token_id

    def keepalive_token(self, token_id):
        if isinstance(token_id, Token):
            token = token_id
            token_id = self.lookup_token_id(token)
        else:
            token = self.lookup_token(token_id)
            if not token:
                raise TokenException('Token not found or expired')

        if token.lifetime:
            gevent.kill(token.timer)
            if token.revocation_function is not None:
                token.timer = gevent.spawn_later(
                    token.lifetime,
                    token.revocation_function,
                    self,
                    token,
                    token_id
                )
            else:
                token.timer = gevent.spawn_later(
                    token.lifetime,
                    self.revoke_token,
                    token_id
                )

    def lookup_token(self, token_id):
        return self.tokens.get(token_id)

    def lookup_token_id(self, token):
        for key, value in self.tokens.items():
            if value == token:
                return key

    def delete_token(self, token_id):
        if isinstance(token_id, Token):
            token = token_id
            token_id = self.lookup_token_id(token)
        else:
            token = self.lookup_token(token_id)
            if not token:
                logger.trace('Tried to delete token but it was not found or expired')
                return
        if token.lifetime:
            gevent.kill(token.timer)
            token.revocation_reason = 'Token explicitly deleted'
            token.revocation_function(self, token, token_id)
        else:
            self.tokens.pop(token)

    def revoke_token(self, token_id):
        self.tokens.pop(token_id, None)
