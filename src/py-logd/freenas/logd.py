#
# Copyright 2017 iXsystems, Inc.
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
import sys
import logging
import traceback
from datetime import datetime
from freenas.dispatcher.client import Client


PRIORITY_MAP = {
    logging.DEBUG: 'DEBUG',
    logging.INFO: 'INFO',
    logging.WARNING: 'WARNING',
    logging.ERROR: 'ERROR',
    logging.CRITICAL: 'CRIT'
}


class LogdLogHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET, address=None, ident=None):
        super(LogdLogHandler, self).__init__(level)
        self.address = address or 'unix:///var/run/logd.sock'
        self.ident = ident or os.path.basename(sys.executable)
        self.client = Client()
        self.client.connect(self.address)

    def emit(self, record):
        if not self.client.connected:
            self.client.connect(self.address)

        item = {
            'timestamp': datetime.utcfromtimestamp(record.created),
            'priority': PRIORITY_MAP.get(record.levelno, 'INFO'),
            'message': record.getMessage(),
            'identifier': self.ident,
            'thread': record.threadName,
            'tid': record.thread,
            'module_name': record.name,
            'source_language': 'python',
            'source_file': record.pathname,
            'source_line': record.lineno,
        }

        if record.exc_info:
            item['exception'] = '\n'.join(traceback.format_exception(*record.exc_info))

        try:
            self.client.call_sync('logd.logging.push', item, timeout=20)
        except:
            self.handleError(record)

    def close(self):
        super(LogdLogHandler, self).close()
        self.client.disconnect()
