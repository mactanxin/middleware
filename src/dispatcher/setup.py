#-
# Copyright (c) 2014 iXsystems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import os
import Cython.Compiler.Options
Cython.Compiler.Options.annotate = True
from distutils.core import setup
from Cython.Distutils.extension import Extension
from Cython.Distutils import build_ext


files = [
    "src/auth.py",
    "src/balancer.py",
    "src/cache.py",
    "src/debug.py",
    "src/event.py",
    "src/main.py",
    "src/query.py",
    "src/resources.py",
    "src/schemas.py",
    "src/services.py",
    "src/task.py",
    "src/websocket.py",
    "src/utils.py",
    "src/lib/freebsd.py",
    "src/lib/geom.py",
    "src/lib/system.py",
    "src/lib/zfs.py",
]


def extensions():
    for f in files:
        path = os.path.relpath(f, 'src')
        name, _ = os.path.splitext(path)

        yield Extension(
            name.replace('/', '.'),
            [f],
            extra_compile_args=["-g", "-O0"],
            cython_directives={'language_level': 3}
        )


setup(
    name='dispatcher',
    version='1.0',
    cmdclass={'build_ext': build_ext},
    ext_modules=list(extensions())
)
