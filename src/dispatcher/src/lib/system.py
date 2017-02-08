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

import logging
import subprocess
from freenas.utils.trace_logger import TRACE


logger = logging.getLogger('system')


class SubprocessException(Exception):
    def __init__(self, code, out, err):
        self.returncode = code
        self.out = out
        self.err = err


def system(*args, **kwargs):
    sh = kwargs.pop("shell", False)
    decode = kwargs.pop('decode', True)
    stdin = kwargs.pop('stdin', None)
    merge_stderr = kwargs.pop('merge_stderr', False)

    if stdin:
        stdin = stdin.encode('utf-8')

    proc = subprocess.Popen(
        [a.encode('utf-8') for a in args],
        stdin=subprocess.PIPE if stdin else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if merge_stderr else subprocess.PIPE,
        close_fds=True,
        shell=sh
    )

    out, err = proc.communicate(input=stdin)
    logger.log(TRACE, "Running command: %s", ' '.join(args))

    if decode:
        out = out.decode('utf-8')
        if err:
            err = err.decode('utf-8')

    if proc.returncode != 0:
        logger.log(
            TRACE,
            "Command %s failed, return code %d, stderr output: %s",
            ' '.join(args),
            proc.returncode,
            err or out
        )
        raise SubprocessException(proc.returncode, out, err)

    return out, err


# Only use this for running background processes
# for which you do not want subprocess to wait on
# for the output or error (warning: no error handling)
def system_bg(*args, **kwargs):
    sh = False
    to_log = False
    sh = kwargs["shell"] if "shell" in kwargs else False
    to_log = kwargs["to_log"] if "to_log" in kwargs else True
    subprocess.Popen(args, stderr=subprocess.PIPE, shell=sh,
                     stdout=subprocess.PIPE, close_fds=True)
    if to_log:
        logger.debug("Started command (in background) : %s", ' '.join(args))
