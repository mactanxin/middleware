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


class AttachFile(object):
    def __init__(self, name, path):
        self.name = name
        self.path = path

    def __getstate__(self):
        return {
            'type': 'AttachFile',
            'name': self.name,
            'path': self.path,
            'recursive': False
        }


class AttachDirectory(object):
    def __init__(self, name, path, recursive=True):
        self.name = name
        self.path = path
        self.recursive = recursive

    def __getstate__(self):
        return {
            'type': 'AttachDirectory',
            'name': self.name,
            'path': self.path,
            'recursive': self.recursive
        }


class AttachCommandOutput(object):
    def __init__(self, name, command, shell=False, decode=True):
        self.name = name
        self.command = command
        self.shell = shell
        self.decode = decode

    def __getstate__(self):
        return {
            'type': 'AttachCommandOutput',
            'name': self.name,
            'command': self.command,
            'shell': self.shell,
            'decode': self.decode
        }


class AttachData(object):
    def __init__(self, name, data):
        self.name = name
        self.data = data

    def __getstate__(self):
        return {
            'type': 'AttachData',
            'name': self.name,
            'data': self.data
        }


class AttachRPC(object):
    def __init__(self, name, rpc, args):
        self.name = name
        self.rpc = rpc
        self.args = args

    def __getstate__(self):
        return {
            'type': 'AttachRPC',
            'name': self.name,
            'rpc': self.rpc,
            'args': self.args
        }
