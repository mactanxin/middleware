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

SSHD_KEY_NAME_MAP = {
    'service.sshd.keys.dsa.private': 'service.sshd.keys_dsa_private',
    'service.sshd.keys.dsa.public': 'service.sshd.keys_dsa_public',
    'service.sshd.keys.dsa.certificate': 'service.sshd.keys_dsa_certificate',
    'service.sshd.keys.ecdsa.private': 'service.sshd.keys_ecdsa_private',
    'service.sshd.keys.ecdsa.public': 'service.sshd.keys_ecdsa_public',
    'service.sshd.keys.ecdsa.certificate': 'service.sshd.keys_ecdsa_certificate',
    'service.sshd.keys.ed25519.private': 'service.sshd.keys_ed25519_private',
    'service.sshd.keys.ed25519.public': 'service.sshd.keys_ed25519_public',
    'service.sshd.keys.ed25519.certificate': 'service.sshd.keys_ed25519_certificate',
    'service.sshd.keys.rsa.private': 'service.sshd.keys_rsa_private',
    'service.sshd.keys.rsa.public': 'service.sshd.keys_rsa_public',
    'service.sshd.keys.rsa.certificate': 'service.sshd.keys_rsa_certificate',
}


def probe(obj, ds):
    return obj['id'] in SSHD_KEY_NAME_MAP.keys()


def apply(obj, ds):
    obj['id'] = SSHD_KEY_NAME_MAP[obj['id']]
    return obj
