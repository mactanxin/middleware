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

import base64
import errno
import logging
import os
import smtplib
import socket
from typing import Optional, List
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

from datastore.config import ConfigNode
from freenas.dispatcher.model import BaseStruct, BaseEnum, structures
from freenas.dispatcher.rpc import RpcException, SchemaHelper as h, accepts, description, returns
from task import Provider, Task, ValidationException, TaskDescription

logger = logging.getLogger('MailPlugin')


class MailEncryptionType(BaseEnum):
    PLAIN = 'PLAIN'
    SSL = 'SSL'
    TLS = 'TLS'


class MailMessage(BaseStruct):
    from_address: str
    to: str
    subject: str
    message: str
    attachments: List[str]
    extra_headers: dict


class AlertEmitterEmail(BaseStruct):
    __variant_of__ = structures.AlertEmitterConfig
    from_address: str
    to: List[str]
    server: str
    port: int
    auth: bool
    encryption: MailEncryptionType
    user: Optional[str]
    password: Optional[str]


class AlertEmitterParametersEmail(BaseStruct):
    __variant_of__ = structures.AlertEmitterParameters
    to: List[str]


@description("Provides Information about the mail configuration")
class MailProvider(Provider):
    def get_config(self) -> AlertEmitterEmail:
        node = ConfigNode('mail', self.configstore).__getstate__()
        return AlertEmitterEmail(node)

    @accepts(h.ref('MailMessage'), h.ref('Mail'))
    def send(self, mailmessage, mail=None):

        if mail is None:
            mail = ConfigNode('mail', self.configstore).__getstate__()
        if not mail.get('server') or not mail.get('port'):
            raise RpcException(
                errno.EINVAL,
                'You must provide an outgoing server and port when sending mail',
            )

        to = mailmessage.get('to')
        attachments = mailmessage.get('attachments')
        subject = mailmessage.get('subject')
        extra_headers = mailmessage.get('extra_headers')

        if not to:
            to = self.dispatcher.call_sync('user.query', [('username', '=', 'root')], {'single': True})
            if to and to.get('email'):
                to = [to['email']]

        if attachments:
            msg = MIMEMultipart()
            msg.preamble = mailmessage['message']
            list(map(lambda attachment: msg.attach(attachment), attachments))
        else:
            msg = MIMEText(mailmessage['message'], _charset='utf-8')
        if subject:
            msg['Subject'] = subject

        msg['From'] = mailmessage.get('from_address', mail['from_address'])
        msg['To'] = ', '.join(to)
        msg['Date'] = formatdate()

        local_hostname = socket.gethostname()
        version = self.dispatcher.call_sync('system.info.version').split('-')[0].lower()

        msg['Message-ID'] = "<{0}-{1}.{2}@{3}>".format(
            version,
            datetime.utcnow().strftime("%Y%m%d.%H%M%S.%f"),
            base64.urlsafe_b64encode(os.urandom(3)),
            local_hostname)

        if not extra_headers:
            extra_headers = {}
        for key, val in list(extra_headers.items()):
            if key in msg:
                msg.replace_header(key, val)
            else:
                msg[key] = val
        msg = msg.as_string()

        try:
            if mail['encryption'] == 'SSL':
                klass = smtplib.SMTP_SSL
            else:
                klass = smtplib.SMTP
            server = klass(mail['server'], mail['port'], timeout=300, local_hostname=local_hostname)
            if mail['encryption'] == 'TLS':
                server.starttls()

            if mail['auth']:
                server.login(mail['user'], mail['pass'])
            server.sendmail(mail['from_address'], to, msg)
            server.quit()
        except smtplib.SMTPAuthenticationError as e:
            raise RpcException(errno.EACCES, 'Authentication error: {0} {1}'.format(
                e.smtp_code, e.smtp_error))
        except Exception as e:
            logger.error('Failed to send email: {0}'.format(str(e)), exc_info=True)
            raise RpcException(errno.EFAULT, 'Email send error: {0}'.format(str(e)))
        except:
            raise RpcException(errno.EFAULT, 'Unexpected error')


@accepts(h.ref('Mail'))
@description('Updates mail configuration')
class MailConfigureTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating mail configuration'

    def describe(self, mail):
        return TaskDescription(
            'Updating {name} mail configuration',
            name=mail.get('user', '') + '@' + mail.get('server', '') if mail else ''
        )

    def verify(self, mail):
        errors = ValidationException()
        node = ConfigNode('mail', self.configstore).__getstate__()

        if mail.get('auth'):
            if not mail.get('user') and not node['user']:
                errors.add((0, 'auth'), 'Mail authorization requires a username')
            if not mail.get('pass') and not node['pass']:
                errors.add((0, 'auth'), 'Mail authorization requires a password')

        if errors:
            raise errors

        return []

    def run(self, mail):
        node = ConfigNode('mail', self.configstore)
        node.update(mail)


def _metadata():
    return {
        'id': '700a2699-f24a-11e6-8277-0cc47a3511b4',
        'type': 'alert_emitter',
        'name': 'email'
    }


def _init(dispatcher, plugin):
    plugin.register_provider('alert.emitter.email', MailProvider)
    plugin.register_task_handler('alert.emitter.email.update', MailConfigureTask)
