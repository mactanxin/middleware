#+
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

import re
import errno
from freenas.dispatcher.rpc import accepts, description, returns, SchemaHelper as h, generator
from task import Provider, Task, VerifyException, query, TaskDescription
from freenas.utils import query as q

# Write plugin names or matching substrings of plugin names
# that report temperature in celsius directly
CELSIUS_STATS = ['disktemp']


def temp_normalize(name, value):
    if value in [-1, None]:
        value = None
    elif not any(x in name for x in CELSIUS_STATS):
        value = (value - 2732) / 10
    return value


def temp_raw(name, value):
    raw = value
    if value is not None and not any(x in name for x in CELSIUS_STATS):
        raw = value * 10 + 2732
    return raw


UNITS = {
    'Ops/s': {
        'match': lambda x: re.match(r'(.*)(disk_merged|disk_ops)(.*)', x),
        'normalize': lambda n, x: x,
        'raw': lambda n, x: x
    },
    'B/s': {
        'match': lambda x: re.match(r'(.*)(disk_octets|if_octets)(.*)', x),
        'normalize': lambda n, x: x,
        'raw': lambda n, x: x
    },
    'B': {
        'match': lambda x: re.match(r'(.*)(df-|memory)(.*)', x),
        'normalize': lambda n, x: x,
        'raw': lambda n, x: x
    },
    'C': {
        'match': lambda x: re.match(r'(.*)(temperature)(.*)', x),
        'normalize': temp_normalize,
        'raw': temp_raw
    },
    'Jiffies': {
        'match': lambda x: re.match(r'(.*)(cpu-)(.*)', x),
        'normalize': lambda n, x: x,
        'raw': lambda n, x: x
    },
    'Packets/s': {
        'match': lambda x: re.match(r'(.*)(if_packets)(.*)', x),
        'normalize': lambda n, x: x,
        'raw': lambda n, x: x
    },
    'Errors/s': {
        'match': lambda x: re.match(r'(.*)(if_errors)(.*)', x),
        'normalize': lambda n, x: x,
        'raw': lambda n, x: x
    }
}


@description('Provides information about statistics')
class StatProvider(Provider):
    @query('Statistic')
    @generator
    def query(self, filter=None, params=None):
        stats = self.dispatcher.call_sync('statd.output.get_current_state')
        return q.query(stats, *(filter or []), stream=True, **(params or {}))

    @returns(h.array(str))
    @generator
    def get_data_sources(self):
        return self.dispatcher.call_sync('statd.output.get_data_sources')

    def get_data_sources_tree(self):
        return self.dispatcher.call_sync('statd.output.get_data_sources_tree')

    @accepts(h.one_of(str, h.array(str)), h.ref('GetStatsParams'))
    @returns(h.ref('GetStatsResult'))
    def get_stats(self, data_source, params):
        return {
            'data': list(self.dispatcher.call_sync('statd.output.get_stats', data_source, params))
        }

    def normalize(self, name, value):
        return normalize(name, value)


@description('Provides information about CPU statistics')
class CpuStatProvider(Provider):
    @query('Statistic')
    @generator
    def query(self, filter=None, params=None):
        def extend(stat):
            type = stat['name'].split('.', 3)[2]
            if 'aggregation' in stat['name']:
                stat['short_name'] = dash_to_underscore('aggregated-' + type)
            else:
                stat['short_name'] = dash_to_underscore('cpu-' + re.search(r'\d+', stat['name']).group() + '-' + type)

            normalize_values(stat)
            return stat

        raw_stats = self.dispatcher.call_sync('stat.query', [('name', '~', 'cpu')])
        stats = map(extend, raw_stats)

        return q.query(stats, *(filter or []), stream=True, **(params or {}))


@description('Provides information about disk statistics')
class DiskStatProvider(Provider):
    @query('Statistic')
    @generator
    def query(self, filter=None, params=None):
        def extend(stat):
            split_name = stat['name'].split('.', 3)
            short_name = f'{split_name[1]}_{split_name[3]}'
            if '_' in split_name[2]:
                short_name += '_{}'.format(split_name[2].split('_')[-1])

            stat['short_name'] = dash_to_underscore(short_name)

            normalize_values(stat)
            return stat

        raw_stats = self.dispatcher.call_sync('stat.query', [('name', '~', 'disk')])
        stats = map(extend, raw_stats)

        return q.query(stats, *(filter or []), stream=True, **(params or {}))


@description('Provides information about network statistics')
class NetworkStatProvider(Provider):
    @query('Statistic')
    @generator
    def query(self, filter=None, params=None):
        def extend(stat):
            split_name = stat['name'].split('.', 3)
            stat['short_name'] = dash_to_underscore(
                split_name[1] + '-' + split_name[3] + '-' + split_name[2].split('_', 2)[1]
            )

            normalize_values(stat)
            return stat

        raw_stats = self.dispatcher.call_sync('stat.query', [('name', '~', 'interface')])
        stats = map(extend, raw_stats)

        return q.query(stats, *(filter or []), stream=True, **(params or {}))


@description('Provides information about system statistics')
class SystemStatProvider(Provider):
    @query('Statistic')
    @generator
    def query(self, filter=None, params=None):
        def extend(stat):
            split_name = stat['name'].split('.', 3)
            if 'df' in stat['name']:
                stat['short_name'] = dash_to_underscore(
                    split_name[1].split('-', 1)[1] + '-' + split_name[2].split('-', 1)[1]
                )
            elif 'load' in stat['name']:
                stat['short_name'] = dash_to_underscore(split_name[1] + '-' + split_name[3])
            else:
                stat['short_name'] = dash_to_underscore(split_name[2])

            normalize_values(stat)
            return stat

        raw_stats = self.dispatcher.call_sync(
            'stat.query',
            [
                ['or', [('name', '~', 'load'), ('name', '~', 'processes'), ('name', '~', 'memory'), ('name', '~', 'df')]],
                ['nor', [('name', '~', 'zfs')]]
            ]
        )
        stats = map(extend, raw_stats)

        return q.query(stats, *(filter or []), stream=True, **(params or {}))


@accepts(str, h.ref('Statistic'))
@description('Updates alert levels on a given statistic')
class UpdateAlertTask(Task):
    @classmethod
    def early_describe(cls):
        return 'Updating alert levels of statistic'

    def describe(self, name, stat):
        return TaskDescription('Updating alert levels of statistic {name}', name=name)

    def verify(self, name, stat):
        if name not in self.dispatcher.call_sync('statd.output.get_data_sources'):
            raise VerifyException(errno.ENOENT, 'Statistic {0} not found.'.format(name))
        return ['system']

    def run(self, name, stat):
        updated_alerts = stat.get('alerts')

        for field in updated_alerts:
            if isinstance(updated_alerts[field], bool):
                self.dispatcher.call_sync(
                    'statd.alert.set_alert',
                    name,
                    field,
                    updated_alerts[field]
                )
            elif field in ['alert_high', 'alert_low']:
                self.dispatcher.call_sync(
                    'statd.alert.set_alert',
                    name,
                    field,
                    raw(name, updated_alerts[field])
                )

        self.dispatcher.dispatch_event('stat.alert.changed', {
            'operation': 'update',
            'ids': [name]
        })


def normalize_values(stat):
    stat['unit'], stat['normalized_value'] = normalize(stat['name'], stat['last_value'])
    stat['unit'], stat['alerts']['normalized_alert_high'] = normalize(stat['name'], stat['alerts']['alert_high'])
    stat['unit'], stat['alerts']['normalized_alert_low'] = normalize(stat['name'], stat['alerts']['alert_low'])


def normalize(name, value):
    for key, unit in UNITS.items():
        if unit['match'](name):
            return key, unit['normalize'](name, value)

    return '', value


def raw(name, value):
    for key, unit in UNITS.items():
        if unit['match'](name):
            return unit['raw'](name, value)

    return value


def dash_to_underscore(name):
    return name.replace('-', '_')


def _init(dispatcher, plugin):
    plugin.register_schema_definition('Statistic', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'name': {'type': 'string'},
            'short_name': {'type': 'string'},
            'unit': {'type': 'string'},
            'last_value': {'type': ['integer', 'number', 'null']},
            'alerts': {'$ref': 'StatisticAlert'},
        }
    })
    plugin.register_schema_definition('StatisticAlert', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'alert_high': {'type': ['integer', 'number', 'null']},
            'normalized_alert_high': {'type': ['integer', 'number', 'null']},
            'alert_high_enabled': {'type': 'boolean'},
            'alert_low': {'type': ['integer', 'number', 'null']},
            'normalized_alert_low': {'type': ['integer', 'number', 'null']},
            'alert_low_enabled': {'type': 'boolean'}
        }
    })

    plugin.register_provider('stat', StatProvider)
    plugin.register_provider('stat.cpu', CpuStatProvider)
    plugin.register_provider('stat.disk', DiskStatProvider)
    plugin.register_provider('stat.network', NetworkStatProvider)
    plugin.register_provider('stat.system', SystemStatProvider)
    plugin.register_task_handler('stat.alert_update', UpdateAlertTask)
    plugin.register_event_type('stat.alert.changed')

