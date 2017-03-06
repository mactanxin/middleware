#
# Copyright 2014-2016 iXsystems, Inc.
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
import socket
from mako.template import Template
from main import AlertEmitter


TEMPLATES_ROOT = '/usr/local/lib/alertd/templates'


class EmailEmitter(AlertEmitter):
    def emit_first(self, alert, options):
        tmpl = Template(filename=os.path.join(TEMPLATES_ROOT, 'email_first.mako'))
        to = options.get('to')

        if to:
            self.context.client.call_sync('alert.emitter.email.send', {
                'to': to,
                'subject': '{0}: {1}'.format(socket.gethostname(), alert['title']),
                'message': tmpl.render(cls=alert['clazz'], **alert),
            })

    def emit_again(self, alert, options):
        tmpl = Template(filename=os.path.join(TEMPLATES_ROOT, 'email_again.mako'))
        to = options.get('to')

        if to:
            self.context.client.call_sync('alert.emitter.email.send', {
                'to': to,
                'subject': '{0}: {1}'.format(socket.gethostname(), alert['title']),
                'message': tmpl.render(cls=alert['clazz'], **alert),
            })

    def cancel(self, alert, options):
        tmpl = Template(filename=os.path.join(TEMPLATES_ROOT, 'email_cancel.mako'))
        to = options.get('to')

        if to:
            self.context.client.call_sync('alert.emitter.email.send', {
                'to': to,
                'subject': '{0}: {1} cancelled'.format(socket.gethostname(), alert['title']),
                'message': tmpl.render(cls=alert['clazz'], **alert),
            })


def _init(context):
    context.register_emitter('email', EmailEmitter)
