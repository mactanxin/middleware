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


def _depends():
    return ['AlertPlugin']


def _init(dispatcher, plugin):
    def on_client_login(args):
        dispatcher.call_sync('alert.emit', {
            'clazz': 'UserLogin',
            'one_shot': True,
            'target': args['username'],
            'title': 'User {0} has logged in'.format(args['username']),
            'description': 'User {username} has logged in from {address}'.format(**args)
        })

    def on_client_logout(args):
        dispatcher.call_sync('alert.emit', {
            'clazz': 'UserLogout',
            'one_shot': True,
            'target': args['username'],
            'title': 'User {0} has logged out'.format(args['username']),
            'description': 'User {username} has logged out'.format(**args)
        })

    plugin.register_event_handler('server.client_login', on_client_login)
    plugin.register_event_handler('server.client_logout', on_client_logout)
