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

import logging
import errno
import netif
import threading
from binascii import crc32
from utils import uuid2, parse_uuid2
from bsd.nis import NIS, NISError
from freenas.utils import normalize
from freenas.utils.query import query
from plugin import DirectoryServicePlugin, DirectoryState

logger = logging.getLogger(__name__)


class NISPlugin(DirectoryServicePlugin):
    def __init__(self, context):
        self.context = context
        self.server = None
        self.directory = None
        self.parameters = None
        self.enabled = False
        self.domain_name = None
        self.server_name = None
        self.bind_thread = threading.Thread(target=self.bind, daemon=True)
        self.cv = threading.Condition()
        self.bind_thread.start()

    @staticmethod
    def normalize_parameters(parameters):
        return normalize(parameters, {
            '%type': 'nis-directory-params',
            'server': None
        })

    def _convert_user(self, entry):
        tmp = (self.domain_name or "").encode('utf-8')
        
        retval = {
            'id': str(uuid2(crc32(tmp), entry.pw_uid)),
            'uid': entry.pw_uid,
            'gid': entry.pw_gid,
            'builtin': False,
            'username': entry.pw_name,
            'full_name': entry.pw_gecos,
            'shell': entry.pw_shell,
            'home': entry.pw_dir,
            'sshpubkey': None,
            'group': str(uuid2(crc32(tmp), entry.pw_gid)),
            'groups': None,
            'sudo': False,
            }
        if entry.pw_passwd and entry.pw_passwd != "*":
            retval['unixhash'] = entry.pw_passwd
        else:
            retval['unixhash'] = None

        return retval
    
    def _convert_group(self, entry):
        tmp = (self.domain_name or "").encode('utf-8')
        return {
            'id': str(uuid2(crc32(tmp), int(entry.gr_gid))),
            'gid': entry.gr_gid,
            'name': entry.gr_name,
            'parents': None,
            'builtin': False,
            'sudo': False,
            }
    
    def getpwent(self, filter=None, params=None):
        filter = filter or []
        filter.append(('uid', '!=', 0))
        return query((self._convert_user(pw) for pw in self.server.getpwent()),
                     *filter, **(params or {}))

    def getpwnam(self, name):
        if name == "root":
            return None
        return self._convert_user(self.server.getpwnam(name))

    def getpwuid(self, uid):
        if uid == 0:
            return None
        return self._convert_user(self.server.getpwuid(uid))

    def getpwuuid(self, uuid):
        tmp = (self.domain_name or "").encode('utf-8')
        (checksum, uid) = parse_uuid2(uuid)
        if crc32(tmp) != checksum:
            return None
        return self._convert_user(self.server.getpwuid(uid))

    def getgrent(self, filter=None, params=None):
        filter = filter or []
        filter.append(('gid', '!=', 0))
        return query((self._convert_group(gr) for gr in self.server.getgrent()),
                     *filter, **(params or {}))

    def getgrnam(self, name):
        return self._convert_group(self.server.getgrnam(name))

    def getgrgid(self, gid):
        if gid == 0:
            return None
        return self._convert_group(self.server.getgrgid(gid))

    def getgruuid(self, uuid):
        tmp = (self.domain_name or "").encode('utf-8')
        (checksum, gid) = parse_uuid2(uuid)
        if crc32(tmp) != checksum:
            return None
        tmp = self.server.getgrgid(gid)
        retval = self._convert_group(tmp)
        return retval

    def change_password(self, username, password):
        # Not currently implemented, or at least not implemented well
        raise OSError(errno.EPERM)

    def bind(self):
        while True:
            with self.cv:
                notify = self.cv.wait(60)

                if self.enabled:
                    if self.directory.state == DirectoryState.BOUND and not notify:
                        continue

                    self.directory.put_state(DirectoryState.JOINING)
                    self.domain_name = self.parameters.get("domain")
                    self.server_name = self.parameters.get("server")

                    # I don't think this is right.
                    # Should probably use get_domainname() if it's None?
                    if self.domain_name:
                        netif.set_domainname(self.domain_name)
                        
                    if self.server_name is None:
                        try:
                            self.context.client.call_sync('service.ensure_started', 'ypbind')
                        except:
                            logger.debug("Unable to start ypbind", exc_info=True)

                    try:
                        self.server = NIS(self.domain_name, self.server_name)
                        self.directory.put_state(DirectoryState.BOUND)
                    except NISError as err:
                        s = "Unable to bind to domain {} using server {}".format(self.domain_name, self.server_name)
                        logger.debug(s, exc_info=True)
                        self.directory.put_status(errno.ECONNREFUSED, s)
                        self.directory.put_state(DirectoryState.FAILURE)
                else:
                    if self.directory.state != DirectoryState.DISABLED:
                        self.server = None
                        self.domain_name = None
                        self.server_name = None
                        self.directory.put_state(DirectoryState.DISABLED)
                continue
                        
    def configure(self, enable, directory):
        with self.cv:
            self.directory = directory
            self.parameters = directory.parameters
            self.enabled = enable
            self.cv.notify_all()
            
        return directory.parameters.get("domain")


def _init(context):
    context.register_plugin('nis', NISPlugin)

    context.register_schema('nis-directory-params', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            '%type': {'enum': ['nis-directory-params']},
            'server': {'type': ['string', 'null']},
            'domain': {'type': 'string'}
        }
    })
