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

import itertools


def compare_vdevs(vd1, vd2):
    if vd1 is None or vd2 is None:
        return False

    if vd1['guid'] != vd2['guid']:
        return False

    if vd1['type'] != vd2['type']:
        return False

    if vd1.get('path') != vd2.get('path'):
        return False

    for c1, c2 in itertools.zip_longest(vd1.get('children', []), vd2.get('children', [])):
        if not compare_vdevs(c1, c2):
            return False

    return True


def iterate_vdevs(topology):
    for name, grp in list(topology.items()):
        def iterate_group(g):
            for vdev in g:
                if vdev['type'] == 'disk':
                    yield vdev, name
                    continue

                if 'children' in vdev:
                    yield from iterate_group(vdev['children'])

        yield from iterate_group(grp)


def vdev_by_guid(topology, guid):
    for vd, _ in iterate_vdevs(topology):
        if vd['guid'] == guid:
            return vd


def vdev_by_path(topology, path):
    for vd, _ in iterate_vdevs(topology):
        if vd.get('path') == path:
            return vd


def split_snapshot_name(name):
    ds, _, snap = name.partition('@')
    pool = ds.split('/', 1)[0]
    return pool, ds, snap


def get_disks(topology):
    for vdev, gname in iterate_vdevs(topology):
        yield vdev['path'], gname


def get_disk_ids(topology):
    for vdev, _ in iterate_vdevs(topology):
        id = vdev.get('disk_id')
        if id:
            yield id


def get_resources(topology):
    return [f'disk:{d}' for d in get_disk_ids(topology)]
