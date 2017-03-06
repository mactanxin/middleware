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

from threading import Lock
from freenas.dispatcher.client import Client
from freenas.dispatcher.rpc import RpcException


SERVICED_SOCKET = 'unix:///var/run/serviced.sock'
_client = Client()
_lock = Lock()


class ServicedException(RpcException):
    pass


def checkin():
    with _lock:
        try:
            _client.connect(SERVICED_SOCKET)
            return _client.call_sync('serviced.job.checkin')
        except RpcException as err:
            raise ServicedException(err.code, err.message, err.extra)
        finally:
            _client.disconnect()


def push_status(status, extra=None):
    with _lock:
        try:
            _client.connect(SERVICED_SOCKET)
            return _client.call_sync('serviced.job.push_status', status, extra)
        except RpcException as err:
            raise ServicedException(err.code, err.message, err.extra)
        finally:
            _client.disconnect()


def subscribe(callback):
    with _lock:
        try:
            _client.connect(SERVICED_SOCKET)
            _client.subscribe_events('serviced.*')
            _client.on_event(callback)
        except RpcException as err:
            raise ServicedException(err.code, err.message, err.extra)


def get_job_by_pid(pid, fuzzy=False):
    with _lock:
        try:
            _client.connect(SERVICED_SOCKET)
            return _client.call_sync('serviced.job.get_by_pid', pid, fuzzy)
        except RpcException as err:
            raise ServicedException(err.code, err.message, err.extra)
        finally:
            _client.disconnect()


def unsubscribe():
    with _lock:
        _client.on_event = None
        _client.disconnect()
