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

from gevent.event import Event
from gevent.lock import RLock
from freenas.utils.query import query, set
from sortedcontainers import SortedDict


class CacheStore(object):
    class CacheItem(object):
        __slots__ = ('valid', 'data')

        def __init__(self):
            self.valid = Event()
            self.data = None

    def __init__(self, key=None):
        self.lock = RLock()
        self.store = SortedDict(key)

    def __getitem__(self, item):
        return self.get(item)

    def put(self, key, data):
        with self.lock:
            try:
                item = self.store[key]
                item.data = data
                item.valid.set()
                return False
            except KeyError:
                item = self.CacheItem()
                item.data = data
                item.valid.set()
                self.store[key] = item
                return True

    def update(self, **kwargs):
        with self.lock:
            created = []
            updated = []
            for k, v in kwargs.items():
                if not v:
                    continue

                try:
                    item = self.store[k]
                    created.append(k)
                except KeyError:
                    item = self.CacheItem()
                    self.store[k] = item
                    updated.append(k)

                item.data = v
                item.valid.set()

            return created, updated

    def update_one(self, key, **kwargs):
        with self.lock:
            item = self.get(key)
            if not item:
                return False

            for k, v in kwargs.items():
                set(item, k, v)

            self.put(key, item)
            return True

    def update_many(self, key, predicate, **kwargs):
        with self.lock:
            updated = []
            for k, v in self.itervalid():
                if predicate(v):
                    if self.update_one(k, **kwargs):
                        updated.append(key)

            return updated

    def get(self, key, default=None, timeout=None):
        item = self.store.get(key)
        if item:
            item.valid.wait(timeout)
            return item.data

        return default

    def remove(self, key):
        with self.lock:
            try:
                del self.store[key]
                return True
            except KeyError:
                return False

    def remove_many(self, keys):
        with self.lock:
            removed = []
            for key in keys:
                try:
                    del self.store[key]
                    removed.append(key)
                except KeyError:
                    pass

            return removed

    def clear(self):
        with self.lock:
            items = list(self.store.keys())
            self.store.clear()
            return items

    def exists(self, key):
        return key in self.store

    def rename(self, oldkey, newkey):
        with self.lock:
            obj = self.get(oldkey)
            if not obj:
                return
            obj['id'] = newkey
            self.put(newkey, obj)
            self.remove(oldkey)

    def rename_many(self, pairs):
        for o, n in pairs:
            self.rename(o, n)

    def is_valid(self, key):
        item = self.store.get(key)
        if item:
            return item.valid.is_set()

        return False

    def invalidate(self, key):
        with self.lock:
            item = self.store.get(key)
            if item:
                item.valid.clear()

    def itervalid(self):
        for key, value in list(self.store.items()):
            if value.valid.is_set():
                yield (key, value.data)

    def validvalues(self):
        for value in list(self.store.values()):
            if value.valid.is_set():
                yield value.data

    def remove_predicate(self, predicate):
        result = []
        for k, v in self.itervalid():
            if predicate(v):
                self.remove(k)
                result.append(k)

        return result

    def query(self, *filter, **params):
        return query(list(self.validvalues()), *filter, **params)


class EventCacheStore(CacheStore):
    def __init__(self, dispatcher, name, key=None):
        super(EventCacheStore, self).__init__(key=key)
        self.dispatcher = dispatcher
        self.ready = False
        self.name = name

    def put(self, key, data):
        ret = super(EventCacheStore, self).put(key, data)
        if self.ready:
            self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                'operation': 'create' if ret else 'update',
                'ids': [key]
            })

        return ret

    def update(self, **kwargs):
        created, updated = super(EventCacheStore, self).update(**kwargs)
        if self.ready:
            if created:
                self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                    'operation': 'create',
                    'ids': created
                })
            if updated:
                self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                    'operation': 'update',
                    'ids': updated
                })

        return created, updated

    def update_one(self, key, **kwargs):
        if super(EventCacheStore, self).update_one(key, **kwargs):
            self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                'operation': 'update',
                'ids': [key]
            })

    def update_many(self, key, predicate, **kwargs):
        updated = super(EventCacheStore, self).update_many(key, predicate, **kwargs)
        self.dispatcher.emit_event('{0}.changed'.format(self.name), {
            'operation': 'update',
            'ids': updated
        })

    def remove(self, key):
        ret = super(EventCacheStore, self).remove(key)
        if ret and self.ready:
            self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                'operation': 'delete',
                'ids': [key]
            })

        return ret

    def remove_many(self, keys):
        ret = super(EventCacheStore, self).remove_many(keys)
        if ret and self.ready:
            self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                'operation': 'delete',
                'ids': ret
            })

        return ret

    def clear(self):
        ret = super(EventCacheStore, self).clear()
        if ret and self.ready:
            self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                'operation': 'delete',
                'ids': ret
            })

        return ret

    def rename(self, oldkey, newkey):
        with self.lock:
            super(EventCacheStore, self).rename(oldkey, newkey)

        if self.ready:
            self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                'operation': 'rename',
                'ids': [[oldkey, newkey]]
            })

        return True

    def rename_many(self, pairs):
        with self.lock:
            super(EventCacheStore, self).rename_many(pairs)

        if self.ready:
            self.dispatcher.emit_event('{0}.changed'.format(self.name), {
                'operation': 'rename',
                'ids': [pairs]
            })

    def propagate(self, event, callback=None):
        with self.lock:
            if event['operation'] == 'delete':
                self.remove_many(event['ids'])
                return

            if event['operation'] == 'rename':
                self.rename_many(event['ids'])
                return

            if event['operation'] in ('create', 'update'):
                self.update(**{i['id']: (callback(i) if callback else i) for i in event['entities']})

    def populate(self, collection, callback=None):
        with self.lock:
            for i in collection:
                obj = callback(i) if callback else i
                if obj is not None:
                    self.put(obj['id'], obj)
