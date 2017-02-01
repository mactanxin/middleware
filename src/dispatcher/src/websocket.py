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

from geventwebsocket import WebSocketApplication, WebSocketServer, WebSocketError, Resource
from freenas.dispatcher.transport import ServerTransport, server_transport


class ServerResource(Resource):
    def __init__(self, apps=None, parent=None):
        super(ServerResource, self).__init__(apps)
        self.parent = parent

    def __call__(self, environ, start_response):
        environ = environ
        current_app = self._app_by_path(environ['PATH_INFO'], 'wsgi.websocket' in environ)

        if current_app is None:
            raise Exception("No apps defined")

        if 'wsgi.websocket' in environ:
            ws = environ['wsgi.websocket']
            current_app = current_app(ws, self.parent)
            current_app.ws = ws  # TODO: needed?
            current_app.handle()

            return None
        else:
            return current_app(environ, start_response)


class ServerApplication(WebSocketApplication):
    def __init__(self, ws, parent):
        super(ServerApplication, self).__init__(ws)
        self.parent = parent
        self.conn = None

    @property
    def client_address(self):
        if self.ws.environ:
            if 'HTTP_X_REAL_IP' in self.ws.environ and 'HTTP_X_REAL_PORT' in self.ws.environ:
                return self.ws.environ['HTTP_X_REAL_IP'], int(self.ws.environ['HTTP_X_REAL_PORT'])

        return self.ws.handler.client_address[:2]

    def close(self):
        self.ws.close()

    def send(self, message, fds):
        if self.ws.closed:
            return

        try:
            self.ws.send(message)
        except WebSocketError as err:
            pass

    def on_open(self):
        self.conn = self.parent.on_connection(self)
        self.conn.on_open()

    def on_message(self, message):
        if message is not None:
            self.conn.on_message(message)

    def on_close(self, reason):
        self.conn.on_close(reason)


@server_transport('ws')
class ServerTransportWS(ServerTransport):
    def __init__(self, scheme, parsed_uri, apps=None, kwargs=None):
        super(ServerTransportWS, self).__init__()

        assert scheme == 'ws'
        self.wss = None
        self.address = parsed_uri.hostname
        self.port = parsed_uri.port
        self.apps = apps or {}
        self.apps[parsed_uri.path] = ServerApplication
        self.kwargs = kwargs or {}

    def serve_forever(self, server):
        self.wss = WebSocketServer(
            (self.address, self.port),
            ServerResource(self.apps, server),
            **self.kwargs
        )

        self.wss.serve_forever()
