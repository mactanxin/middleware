#!/usr/local/bin/python3
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

import logging
import argparse
import time
from bsd import setproctitle
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.rpc import RpcService, RpcException, generator
from freenas.utils import configure_logging, load_module_from_file
from freenas.utils.debug import DebugService
from freenas.cli.repl import Context, MainLoop
from freenas.cli.parser import parse, dump_ast, read_ast


DEFAULT_CONFIGFILE = '/usr/local/etc/middleware.conf'
PLUGIN_DIRS = ['/usr/local/lib/python3.6/site-packages/freenas/cli/plugins']


class ManagementService(RpcService):
    def __init__(self, ctx):
        self.context = ctx

    def die(self):
        pass


class EvalService(RpcService):
    def __init__(self, context):
        self.context = context

    @generator
    def eval_ast(self, ast, user):
        ast = read_ast(ast)
        return self.context.ml.eval(ast)

    @generator
    def eval_code(self, code, user):
        ast = parse(code, '<remote eval>')
        return self.context.ml.eval(ast)

    def parse(self, code):
        return dump_ast(parse(code, '<remote eval>'))


class Main(object):
    def __init__(self):
        self.logger = logging.getLogger('clid')
        self.config = None
        self.datastore = None
        self.configstore = None
        self.client = None
        self.config = None
        self.logger = logging.getLogger()
        self.plugin_dirs = []
        self.ml = None
        self.context = None

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect()

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def init_cli(self):
        self.logger.info('Initializing CLI instance')
        self.context = Context()
        self.context.connection = self.client
        self.context.plugin_dirs = PLUGIN_DIRS
        self.context.discover_plugins()
        self.context.start_entity_subscribers()
        self.context.login_plugins()
        self.ml = MainLoop(self.context)
        self.logger.info('CLI instance ready')

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('clid')
                self.client.enable_server()
                self.client.call_sync('management.enable_features', ['streaming_responses'])
                self.client.register_service('clid.management', ManagementService(self))
                self.client.register_service('clid.eval', EvalService(self))
                self.client.register_service('clid.debug', DebugService())
                self.client.resume_service('clid.management')
                self.client.resume_service('clid.eval')
                self.client.resume_service('clid.debug')
                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Middleware config file')
        args = parser.parse_args()
        self.config = args.c
        configure_logging('clid', 'DEBUG')

        setproctitle('clid')
        self.init_dispatcher()
        self.init_cli()
        self.client.wait_forever()


if __name__ == '__main__':
    m = Main()
    m.main()

