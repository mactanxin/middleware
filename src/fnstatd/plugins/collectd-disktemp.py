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

# One cannot simply import collectd in a python interpreter (for various reasons)
# thus adding this workaround for standalone testing
if __name__ == '__main__':
    class CollectdDummy:
        def register_config(self, a):
            # do something
            pass

        def register_init(self, a):
            a()

        def register_read(self, a, b=10):
            a()

        def info(self, msg):
            print(msg)

        def warning(self, msg):
            print(msg)

        def debug(self, msg):
            print(msg)

        def error(self, msg):
            print(msg)

        class Values(object):
            def __init__(self, *args, **kwargs):
                self.plugin = ''
                self.plugin_instance = ''
                self.type = None
                self.type_instance = None
                self.values = None
                self.meta = None

            def dispatch(self):
                pass

    collectd = CollectdDummy()
else:
    import collectd
import time
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.rpc import RpcException
from freenas.dispatcher.entity import EntitySubscriber

PLUGIN_NAME = "disktemp"

context = None
ENTITY_SUBSCRIBERS = ['disk']


collectd.info("Loading custom python plugin: {0}".format(PLUGIN_NAME))


class Context(object):
    def __init__(self, *args, **kwargs):
        self.client = None
        self.entity_subscribers = {}

    def start_entity_subscribers(self):
        for i in ENTITY_SUBSCRIBERS:
            if i in self.entity_subscribers:
                self.entity_subscribers[i].stop()
                del self.entity_subscribers[i]

            e = EntitySubscriber(self.client, i)
            e.start()
            self.entity_subscribers[i] = e

    def wait_entity_subscribers(self):
        for i in self.entity_subscribers.values():
            i.wait_ready()

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('collectd_{0}'.format(PLUGIN_NAME))
                # enable streaming responses as they are needed but entitysubscriber for
                # reliable performace and such
                self.client.call_sync('management.enable_features', ['streaming_responses'])
                self.start_entity_subscribers()
                self.wait_entity_subscribers()
                return
            except (OSError, RpcException) as err:
                collectd.warning(
                    "{0} collectd plugin could not connect to server retrying in 5 seconds".format(PLUGIN_NAME)
                )
                time.sleep(5)

    def connection_error(self, event, **kwargs):
        if event in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
            collectd.info('{0} collectd plugin connection to dispatcher lost'.format(PLUGIN_NAME))
            self.connect()

    def init_dispatcher(self):
        self.client = Client()
        self.client.on_error(self.connection_error)
        self.connect()

    def disk_temps(self):
        for disk in self.entity_subscribers['disk'].query(('status.smart_info.temperature', '!=', None)):
            yield (disk['name'], disk['status']['smart_info']['temperature'])


def dispatch_value(name, instance, value, data_type='gauge'):
    val = collectd.Values()
    val.plugin = PLUGIN_NAME
    val.plugin_instance = name
    val.type = data_type
    val.type_instance = instance
    val.values = [value, ]
    val.meta = {'0': True}
    val.dispatch()


def read():
    global context
    for name, temperature in context.disk_temps():
        collectd.debug("Disk: {0} temperature: {1}".format(name, temperature))
        dispatch_value(name, 'temperature', temperature)


def init():
    global context
    context = Context()
    context.init_dispatcher()


collectd.register_init(init)
collectd.register_read(read)
