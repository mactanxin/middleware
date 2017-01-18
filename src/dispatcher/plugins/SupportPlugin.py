#
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
import time
import errno
import json
import logging
import requests
import simplejson
from task import Task, Provider, TaskException, TaskDescription
from freenas.dispatcher.rpc import RpcException, accepts, description, returns
from freenas.dispatcher.rpc import SchemaHelper as h

logger = logging.getLogger('SupportPlugin')
ADDRESS = 'support-proxy.ixsystems.com'
DEFAULT_DEBUG_DUMP_DIR = '/tmp'


@description("Provides access support")
class SupportProvider(Provider):
    @accepts(str, str)
    @returns(h.array(str))
    def categories(self, user, password):
        version = self.dispatcher.call_sync('system.info.version')
        sw_name = version.split('-')[0].lower()
        project_name = '-'.join(version.split('-')[:2]).lower()
        try:
            r = requests.post(
                'https://%s/%s/api/v1.0/categories' % (ADDRESS, sw_name),
                data=json.dumps({
                    'user': user,
                    'password': password,
                    'project': project_name,
                }),
                headers={'Content-Type': 'application/json'},
                timeout=10,
            )
            data = r.json()
        except simplejson.JSONDecodeError as e:
            logger.debug('Failed to decode ticket attachment response: %s', r.text)
            raise RpcException(errno.EINVAL, 'Failed to decode ticket response')
        except requests.ConnectionError as e:
            raise RpcException(errno.ENOTCONN, 'Connection failed: {0}'.format(str(e)))
        except requests.Timeout as e:
            raise RpcException(errno.ETIMEDOUT, 'Connection timed out: {0}'.format(str(e)))

        if 'error' in data:
            raise RpcException(errno.EINVAL, data['message'])

        return data

    @returns(h.array(str))
    def categories_no_auth(self):
        version = self.dispatcher.call_sync('system.info.version')
        sw_name = version.split('-')[0].lower()
        project_name = '-'.join(version.split('-')[:2]).lower()
        try:
            r = requests.post(
                'https://%s/%s/api/v1.0/categoriesnoauth' % (ADDRESS, sw_name),
                data=json.dumps({'project': project_name}),
                headers={'Content-Type': 'application/json'},
                timeout=10,
            )
            data = r.json()
        except simplejson.JSONDecodeError as e:
            logger.debug('Failed to decode ticket attachment response: %s', r.text)
            raise RpcException(errno.EINVAL, 'Failed to decode ticket response')
        except requests.ConnectionError as e:
            raise RpcException(errno.ENOTCONN, 'Connection failed: {0}'.format(str(e)))
        except requests.Timeout as e:
            raise RpcException(errno.ETIMEDOUT, 'Connection timed out: {0}'.format(str(e)))

        if 'error' in data:
            raise RpcException(errno.EINVAL, data['message'])

        return data


@description("Submits a new support ticket")
@accepts(
    h.all_of(
        h.ref('SupportTicket'),
        h.required('subject', 'description', 'category', 'type', 'username', 'password'))
)
class SupportSubmitTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Submitting ticket'

    def describe(self, ticket):
        return TaskDescription('Submitting ticket')

    def verify(self, ticket):
        return ['system']

    def run(self, ticket):
        try:
            version = self.dispatcher.call_sync('system.info.version')
            sw_name = version.split('-')[0].lower()
            project_name = '-'.join(version.split('-')[:2]).lower()
            for attachment in ticket.get('attachments', []):
                attachment = os.path.normpath(attachment)
                if not os.path.exists(attachment):
                    raise TaskException(errno.ENOENT, 'File {} does not exists.'.format(attachment))

            data = {
                'title': ticket['subject'],
                'body': ticket['description'],
                'version': version.split('-', 1)[-1],
                'category': ticket['category'],
                'type': ticket['type'],
                'user': ticket['username'],
                'password': ticket['password'],
                'debug': ticket['debug'] if ticket.get('debug') else False,
                'project': project_name,
            }

            r = requests.post(
                'https://%s/%s/api/v1.0/ticket' % (ADDRESS, sw_name),
                data=json.dumps(data),
                headers={'Content-Type': 'application/json'},
                timeout=10,
            )
            proxy_response = r.json()
            if r.status_code != 200:
                logger.debug('Support Ticket failed (%d): %s', r.status_code, r.text)
                raise TaskException(errno.EINVAL, 'ticket failed (0}: {1}'.format(r.status_code, r.text))

            ticketid = proxy_response.get('ticketnum')
            debug_file_name = os.path.join(
                DEFAULT_DEBUG_DUMP_DIR, version + '_' + time.strftime('%Y%m%d%H%M%S') + '.tar.gz'
            )

            if data['debug']:
                self.run_subtask_sync('debug.save_to_file', debug_file_name)
                if ticket.get('attachments'):
                    ticket['attachments'].append(debug_file_name)
                else:
                    ticket['attachments'] = [debug_file_name]

            for attachment in ticket.get('attachments', []):
                attachment = os.path.normpath(attachment)
                with open(attachment, 'rb') as fd:
                    r = requests.post(
                        'https://%s/%s/api/v1.0/ticket/attachment' % (ADDRESS, sw_name),
                        data={
                            'user': ticket['username'],
                            'password': ticket['password'],
                            'ticketnum': ticketid,
                        },
                        timeout=10,
                        files={'file': (fd.name.split('/')[-1], fd)},
                    )
        except simplejson.JSONDecodeError as e:
            logger.debug("Failed to decode ticket attachment response: %s", r.text)
            raise TaskException(errno.EINVAL, 'Failed to decode ticket response')
        except requests.ConnectionError as e:
            raise TaskException(errno.ENOTCONN, 'Connection failed: {0}'.format(str(e)))
        except requests.Timeout as e:
            raise TaskException(errno.ETIMEDOUT, 'Connection timed out: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(errno.ENXIO, 'Cannot submit support ticket: {0}'.format(str(e)))

        return ticketid, proxy_response.get('message')


def _depends():
    return ['SystemInfoPlugin']


def _init(dispatcher, plugin):
    plugin.register_schema_definition('SupportTicket', {
        'type': 'object',
        'properties': {
            'username': {'type': 'string'},
            'password': {'type': 'string'},
            'subject': {'type': 'string'},
            'description': {'type': 'string'},
            'category': {'type': 'string'},
            'type': {'type': 'string', 'enum': ['bug', 'feature']},
            'debug': {'type': 'boolean'},
            'attachments': {'type': 'array', 'items': {'type': 'string'}},
        },
        'additionalProperties': False,
        'required': ['username', 'password', 'subject', 'description', 'category', 'type', 'debug']
    })

    # Register events
    plugin.register_event_type('support.changed')

    # Register provider
    plugin.register_provider('support', SupportProvider)

    # Register tasks
    plugin.register_task_handler('support.submit', SupportSubmitTask)

