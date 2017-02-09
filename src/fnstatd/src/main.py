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

import gevent.monkey
gevent.monkey.patch_all()

import os
import sys
import re
import math
import errno
import argparse
import logging
import dateutil.parser
import dateutil.tz
import tables
import signal
import time
import collections
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import gevent
import gevent.socket
import gevent.threadpool
from bsd import setproctitle
from gevent.lock import RLock
from gevent.server import StreamServer
from freenas.dispatcher.client import Client, ClientError
from freenas.dispatcher.rpc import RpcService, RpcException, accepts, returns, generator
from datastore import DatastoreException, get_datastore
from ringbuffer import MemoryRingBuffer, PersistentRingBuffer
from freenas.utils.debug import DebugService
from freenas.utils.trace_logger import TRACE
from freenas.utils import configure_logging, to_timedelta, materialized_paths_to_tree
from freenas.serviced import checkin


EVENT_RE = re.compile(r'^statd\.(.*)\.pulse$')
DEFAULT_CONFIGFILE = '/usr/local/etc/middleware.conf'
DEFAULT_DBFILE = 'stats.hdf'
threadpool = gevent.threadpool.ThreadPool(5)


def round_timestamp(timestamp, frequency):
    return int(frequency * round(float(timestamp) / frequency))


def parse_datetime(s):
    return dateutil.parser.parse(s)


def local_to_utc(t):
    return t.astimezone(dateutil.tz.tzutc()).replace(tzinfo=None)


class DataSourceBucket(object):
    def __init__(self, index, obj):
        self.index = index
        self.interval = to_timedelta(obj['interval'])
        self.retention = to_timedelta(obj['retention'])
        self.consolidation = obj.get('consolidation')

    @property
    def covered_start(self):
        return datetime.utcnow() - self.retention

    @property
    def covered_end(self):
        return datetime.utcnow()

    @property
    def intervals_count(self):
        return int(self.retention.total_seconds() / self.interval.total_seconds())


class DataSourceConfig(object):
    def __init__(self, datastore, name):
        self.logger = logging.getLogger('DataSourceConfig:{0}'.format(name))
        name = name if datastore.exists('statd.sources', ('id', '=', name)) else 'default'
        self.ds_obj = datastore.get_by_id('statd.sources', name)
        self.ds_schema = datastore.get_by_id('statd.schemas', self.ds_obj['schema'])
        self.buckets = [DataSourceBucket(idx, i) for idx, i in enumerate(self.ds_schema['buckets'])]
        self.primary_bucket = self.buckets[0]
        self.logger.log(TRACE, 'Created {0} using schema {1}, {2} buckets'.format(
            name,
            self.ds_obj['schema'],
            len(self.buckets))
        )

    @property
    def primary_interval(self):
        return self.primary_bucket.interval

    def get_covered_buckets(self, start, end):
        for i in self.buckets:
            # Bucked should be at least partially covered
            if (start <= i.covered_start <= end) or (i.covered_start <= start <= i.covered_end):
                yield i

            # No need to look further
            if start > i.covered_start:
                return


class DataSource(object):
    def __init__(self, context, name, config, alert_config):
        self.context = context
        self.name = name
        self.config = config
        self.logger = logging.getLogger('DataSource:{0}'.format(self.name))
        self.bucket_buffers = self.create_buckets()
        self.primary_buffer = self.bucket_buffers[0]
        self.primary_interval = self.config.buckets[0].interval
        self.last_value = 0
        self.events_enabled = False
        self.alerts = alert_config

    def create_buckets(self):
        # Primary bucket should be hold in memory
        buckets = [MemoryRingBuffer(self.config.buckets[0].intervals_count)]

        # And others saved to HDF5 file
        for idx, b in enumerate(self.config.buckets[1:]):
            table = self.context.request_table('{0}#b{1}'.format(self.name, idx))
            buckets.append(PersistentRingBuffer(table, b.intervals_count))

        self.logger.log(TRACE, 'Created {0} buckets'.format(len(buckets)))
        return buckets

    def submit(self, timestamp, value):
        timestamp = round_timestamp(timestamp, self.config.primary_interval.total_seconds())
        change = None
        self.primary_buffer.push(timestamp, value)

        for b in self.config.buckets[1:]:
            if timestamp % b.interval.total_seconds() == 0:
                self.persist(timestamp, self.bucket_buffers[b.index], b)

        if math.isnan(value):
            value = None

        if value is not None and self.last_value is not None:
            change = value - self.last_value

        if value is not None and self.events_enabled:
            self.context.push_event('statd.{0}.pulse'.format(self.name), {
                'value': value,
                'change': change,
                'nolog': True
            })

        last_in_range = True
        if self.last_value is not None:
            if (self.alerts['alert_low_enabled']) and (self.last_value < self.alerts['alert_low']):
                last_in_range = False
            elif (self.alerts['alert_high_enabled']) and (self.last_value > self.alerts['alert_high']):
                last_in_range = False

        self.last_value = value

        if value is not None:
            if last_in_range:
                if self.alerts['alert_high_enabled']:
                    if value > self.alerts['alert_high']:
                        self.emit_alert_high()
                if self.alerts['alert_low_enabled']:
                    if value < self.alerts['alert_low']:
                        self.emit_alert_low()

    def persist(self, timestamp, buffer, bucket):
        def doit():
            count = bucket.interval.total_seconds() / self.config.buckets[0].interval.total_seconds()
            data = self.bucket_buffers[0].data
            mean = np.mean(list(zip(*data[-count:]))[1])
            buffer.push(timestamp, mean)

        threadpool.apply(doit)

    def query(self, start, end, frequency):
        self.logger.debug('Query: start={0}, end={1}, frequency={2}'.format(start, end, frequency))
        buckets = list(self.config.get_covered_buckets(start, end))

        def doit():
            df = pd.DataFrame()

            for b in buckets:
                new = self.bucket_buffers[b.index].df
                if new is not None:
                    df = pd.concat((df, new))

            df = df.reset_index().drop_duplicates(subset='index').set_index('index')
            if len(buckets):
                df = df.sort()[0]
                df = df[start:end]
                df = df.resample(frequency, how='mean').interpolate()
            return df

        return threadpool.apply(doit)

    def check_alerts(self):
        if self.last_value is not None:
            if self.alerts['alert_high_enabled']:
                if self.last_value > self.alerts['alert_high']:
                    self.emit_alert_high()

            if self.alerts['alert_low_enabled']:
                if self.last_value < self.alerts['alert_low']:
                    self.emit_alert_low()

    def emit_alert_high(self):
        unit, last_value = self.context.client.call_sync('stat.normalize', self.name, self.last_value)
        unit, alert_high = self.context.client.call_sync('stat.normalize', self.name, self.alerts['alert_high'])

        if last_value:
            self.context.client.call_sync('alert.emit', {
                'name': 'stat.{0}.too_high'.format(self.name),
                'description': 'Value of {0} has exceeded maximum permissible value {1}. Current {2}'.format(
                    self.name,
                    str(alert_high) + unit,
                    str(last_value) + unit
                ),
                'severity': 'WARNING'
            })

    def emit_alert_low(self):
        unit, last_value = self.context.client.call_sync('stat.normalize', self.name, self.last_value)
        unit, alert_low = self.context.client.call_sync('stat.normalize', self.name, self.alerts['alert_low'])

        if last_value:
            self.context.client.call_sync('alert.emit', {
                'name': 'stat.{0}.too_high'.format(self.name),
                'description': 'Value of {0} has gone under minimum permissible value {1}. Current {2}'.format(
                    self.name,
                    str(alert_low) + unit,
                    str(last_value) + unit
                ),
                'severity': 'WARNING'
            })


class InputServer(object):
    def __init__(self, context):
        super(InputServer, self).__init__()
        self.context = context
        self.thread = None
        self.server = StreamServer(('127.0.0.1', 2003), handle=self.handle)

    def start(self):
        self.thread = gevent.spawn(self.server.serve_forever)

    def stop(self):
        gevent.kill(self.thread)

    def handle(self, socket, address):
        fd = socket.makefile()
        while True:
            line = fd.readline()
            if not line:
                break

            name, value, timestamp = line.split()
            _, _, datapoint = name.partition('.')
            ds = self.context.get_data_source('localhost.{0}'.format(datapoint))
            ds.submit(int(timestamp), float(value))

        socket.shutdown(gevent.socket.SHUT_RDWR)
        socket.close()


class OutputService(RpcService):
    def __init__(self, context):
        super(OutputService, self).__init__()
        self.context = context

    def enable(self, event):
        m = EVENT_RE.match(event)
        if not m:
            return

        ds_name = m.group(1)
        ds = self.context.data_sources.get(ds_name)
        if not ds:
            return

        self.context.logger.debug('Enabling event {0}'.format(event))
        ds.events_enabled = True

    def disable(self, event):
        m = EVENT_RE.match(event)
        if not m:
            return

        ds_name = m.group(1)
        ds = self.context.data_sources.get(ds_name)
        if not ds:
            return

        self.context.logger.debug('Disabling event {0}'.format(event))
        ds.events_enabled = False

    def get_data_sources(self):
        return list(self.context.data_sources.keys())

    def get_data_sources_tree(self):
        return materialized_paths_to_tree(self.context.data_sources.keys())

    def get_current_state(self):
        stats = []
        for key, ds in self.context.data_sources.items():
            stats.append({
                'name': ds.name,
                'last_value': ds.last_value,
                'alerts': {
                    'alert_high': ds.alerts['alert_high'],
                    'alert_high_enabled': ds.alerts['alert_high_enabled'],
                    'alert_low': ds.alerts['alert_low'],
                    'alert_low_enabled': ds.alerts['alert_low_enabled']
                }
            })

        return stats

    @generator
    def get_stats(self, data_source, params):
        start = params.pop('start', None)
        end = params.pop('end', datetime.utcnow())
        timespan = params.pop('timespan', None)
        frequency = params.pop('frequency', '10S')

        if start is None and timespan is None:
            raise RpcException(errno.EINVAL, 'Either "start" or "timespan" is required')

        if start is not None and timespan is not None:
            raise RpcException(errno.EINVAL, 'Both "start" and "timespan" specified')

        if timespan is not None:
            start = datetime.utcnow() - timedelta(seconds=timespan)

        if start.tzinfo:
            start = local_to_utc(start)

        if end.tzinfo:
            end = local_to_utc(end)

        if type(data_source) is str:
            ds = self.context.data_sources.get(data_source)
            if not ds:
                raise RpcException(errno.ENOENT, 'Data source {0} not found'.format(data_source))

            df = ds.query(start, end, frequency)
            for i in range(len(df)):
                yield str(df[i])

            return

        if type(data_source) is list:
            final = pd.DataFrame()
            for ds_name in data_source:
                ds = self.context.data_sources.get(ds_name)
                if not ds:
                    raise RpcException(errno.ENOENT, 'Data source {0} not found'.format(ds_name))

                final[ds_name] = ds.query(start, end, frequency)

            for i in range(len(final)):
                yield [str(final[col][i]) for col in data_source]

            return


class AlertService(RpcService):
    def __init__(self, context):
        super(AlertService, self).__init__()
        self.context = context

    def set_alert(self, name, field, value):
        ds = self.context.data_sources[name]

        config_name = name if self.context.datastore.exists('statd.alerts', ('id', '=', name)) else 'default'
        alert_config = ds.alerts

        alert_config[field] = value

        if alert_config['alert_high_enabled'] and (alert_config['alert_high'] is None):
            alert_config['alert_high'] = 0
        if alert_config['alert_low_enabled'] and (alert_config['alert_low'] is None):
            alert_config['alert_low'] = 0

        if config_name == 'default':
            alert_config['id'] = name
            self.context.datastore.insert('statd.alerts', alert_config)
        else:
            self.context.datastore.update('statd.alerts', name, alert_config)

        ds.alerts = alert_config
        ds.check_alerts()


class DataPoint(tables.IsDescription):
    timestamp = tables.Time32Col()
    value = tables.FloatCol()


class Main(object):
    def __init__(self):
        self.client = None
        self.server = None
        self.datastore = None
        self.hdf = None
        self.hdf_group = None
        self.config = None
        self.event_queue = collections.deque()
        self.event_lock = RLock()
        self.logger = logging.getLogger('statd')
        self.data_sources = {}

    def init_datastore(self):
        try:
            self.datastore = get_datastore(self.config)
        except DatastoreException as err:
            self.logger.error('Cannot initialize datastore: %s', str(err))
            sys.exit(1)

    def init_database(self):
        # adding this try/except till system-dataset plugin is added back in in full fidelity
        # just a hack (since that directory's data will not persist)
        # Please remove this when system-dataset plugin is added back in
        try:
            directory = self.client.call_sync('system_dataset.request_directory', 'statd')
        except RpcException:
            directory = '/var/tmp/statd'
            if not os.path.exists(directory):
                os.makedirs(directory)
        self.hdf = tables.open_file(os.path.join(directory, DEFAULT_DBFILE), mode='a')
        if not hasattr(self.hdf.root, 'stats'):
            self.hdf.create_group('/', 'stats')

        self.hdf_group = self.hdf.root.stats

    def request_table(self, name):
        try:
            if hasattr(self.hdf_group, name):
                return getattr(self.hdf_group, name)

            return self.hdf.create_table(self.hdf_group, name, DataPoint, name)
        except Exception as e:
            self.logger.error(str(e))

    def init_alert_config(self, name):
        config_name = name if self.datastore.exists('statd.alerts', ('id', '=', name)) else 'default'
        alert_config = self.datastore.get_by_id('statd.alerts', config_name)
        return alert_config

    def get_data_source(self, name):
        try:
            return self.data_sources[name]
        except KeyError:
            config = DataSourceConfig(self.datastore, name)
            alert_config = self.init_alert_config(name)
            ds = DataSource(self, name, config, alert_config)
            self.data_sources[name] = ds
            self.client.call_sync('plugin.register_event_type', 'statd.output', 'statd.{0}.pulse'.format(name))
            return ds

    def register_schemas(self):
        self.client.register_schema('GetStatsParams', {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'start': {'type': 'datetime'},
                'end': {'type': 'datetime'},
                'timespan': {'type': 'integer'},
                'frequency': {'type': 'string'}
            }
        })

        self.client.register_schema('GetStatsResult', {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'data': {
                    'type': 'array',
                }
            }
        })

    def connect(self):
        while True:
            try:
                self.client.connect('unix:')
                self.client.login_service('statd')
                self.client.enable_server()
                self.register_schemas()
                self.client.register_service('statd.output', OutputService(self))
                self.client.register_service('statd.alert', AlertService(self))
                self.client.register_service('statd.debug', DebugService(gevent=True))
                self.client.resume_service('statd.output')
                self.client.resume_service('statd.alert')
                self.client.resume_service('statd.debug')
                for i in list(self.data_sources.keys()):
                    self.client.call_sync('plugin.register_event_type', 'statd.output', 'statd.{0}.pulse'.format(i))

                return
            except (OSError, RpcException) as err:
                self.logger.warning('Cannot connect to dispatcher: {0}, retrying in 1 second'.format(str(err)))
                time.sleep(1)

    def init_dispatcher(self):
        def on_error(reason, **kwargs):
            if reason in (ClientError.CONNECTION_CLOSED, ClientError.LOGOUT):
                self.logger.warning('Connection to dispatcher lost')
                self.connect()

        self.client = Client()
        self.client.on_error(on_error)
        self.connect()

    def die(self):
        self.logger.warning('Exiting')
        self.server.stop()
        self.client.disconnect()
        sys.exit(0)

    def push_event(self, name, args):
        with self.event_lock:
            self.event_queue.append({
                'name': name,
                'args': args
            })

    def event_worker(self):
        while True:
            time.sleep(1)
            with self.event_lock:
                if self.event_queue and self.client.connected:
                    self.client.send_event_burst(list(self.event_queue))
                    self.event_queue.clear()

    def checkin(self):
        checkin()

    def main(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-c', metavar='CONFIG', default=DEFAULT_CONFIGFILE, help='Middleware config file')
        args = parser.parse_args()
        configure_logging('fnstatd', 'DEBUG')
        setproctitle('fnstatd')

        # Signal handlers
        gevent.signal(signal.SIGQUIT, self.die)
        gevent.signal(signal.SIGTERM, self.die)
        gevent.signal(signal.SIGINT, self.die)
        gevent.spawn(self.event_worker)

        self.server = InputServer(self)
        self.config = args.c
        self.init_datastore()
        self.init_dispatcher()
        self.init_database()
        self.server.start()
        self.logger.info('Started')
        self.checkin()
        self.client.wait_forever()


if __name__ == '__main__':
    m = Main()
    m.main()
