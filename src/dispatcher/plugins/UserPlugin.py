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

import copy
import errno
import os
import re
import shutil
from datetime import datetime
from task import Provider, Task, TaskException, TaskDescription, TaskWarning, ValidationException, VerifyException, query
from debug import AttachFile
from freenas.dispatcher.rpc import RpcException, description, accepts, returns, SchemaHelper as h, generator
from freenas.dispatcher import Password
from datastore import DuplicateKeyException, DatastoreException
from lib.system import SubprocessException, system
from freenas.utils import normalize, crypted_password, nt_password, query as q

EMAIL_REGEX = re.compile(r"^\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,4}\b$")
SKEL_PATH = '/usr/share/skel/'


def normalize_name(d, name):
    if name in d and d[name].endswith('@local'):
        d[name] = d[name].split('@')[0]


def check_unixname(name):
    """Helper method to check if a given name is a valid unix name
        1. Cannot start with dashes
        2. $ is only valid as a final character
        3. Cannot contain any of the following:  ,\t:+&#%\^()!@~\*?<>=|\\/"

    Returns: an array of errors [composed of a tuple (error code, error message)]
    """

    if not name.strip():
        yield errno.EINVAL, 'Name cannot be empty'

    if name.startswith('-'):
        yield errno.EINVAL, 'Your name cannot start with "-"'

    if name.find('$') not in (-1, len(name) - 1):
        yield errno.EINVAL, 'The character $ is only allowed as the final character'

    invalids = []
    for char in name:
        if char in ' ,\t:+&#%\^()!@~\*?<>=|\\/"' and char not in invalids:
            invalids.append(char)

    if invalids:
        yield errno.EINVAL, 'Your name contains invalid characters ({0}).'.format(''.join(invalids))


@description("Provides access to users database")
class UserProvider(Provider):
    @description("Lists users present in the system")
    @query('User')
    @generator
    def query(self, filter=None, params=None):
        if params and params.get('count'):
            return None

        # Common use cases optimization
        if filter and len(filter) == 1 and params and params.get('single'):
            key, op, value = filter[0]
            if op == '=':
                if value is None:
                    return None

                try:
                    if key == 'id':
                        return self.dispatcher.call_sync('dscached.account.getpwuuid', value)

                    if key == 'uid':
                        return self.dispatcher.call_sync('dscached.account.getpwuid', value)

                    if key == 'username':
                        return self.dispatcher.call_sync('dscached.account.getpwnam', value)
                except RpcException as err:
                    if err.code == errno.ENOENT:
                        return None

                    raise

        return q.query(
            self.dispatcher.call_sync('dscached.account.query', filter, params),
            *(filter or []), stream=True, **(params or {})
        )

    def get_profile_picture(self, uid):
        pass

    @description("Retrieve the next UID available")
    @accepts(bool)
    @returns(int)
    def next_uid(self, check_gid=False):
        start_uid, end_uid = self.dispatcher.configstore.get('accounts.local_uid_range')
        uid = None
        for i in range(start_uid, end_uid):
            if check_gid and self.datastore.exists('groups', ('gid', '=', i)):
                continue

            if not self.datastore.exists('users', ('uid', '=', i)):
                uid = i
                break

        if not uid:
            raise RpcException(errno.ENOSPC, 'No free UIDs available')

        return uid


@description("Provides access to groups database")
class GroupProvider(Provider):
    @description("Lists groups present in the system")
    @query('Group')
    @generator
    def query(self, filter=None, params=None):
        if params and params.get('count'):
            return None

        # Common use cases optimization
        if filter and len(filter) == 1 and params and params.get('single'):
            key, op, value = filter[0]
            if op == '=':
                if value is None:
                    return None

                try:
                    if key == 'id':
                        return self.dispatcher.call_sync('dscached.group.getgruuid', value)

                    if key == 'gid':
                        return self.dispatcher.call_sync('dscached.group.getgruid', value)

                    if key == 'name':
                        return self.dispatcher.call_sync('dscached.group.getgrnam', value)
                except RpcException as err:
                    if err.code == errno.ENOENT:
                        return None

                    raise

        return q.query(
            self.dispatcher.call_sync('dscached.group.query', filter, params),
            *(filter or []), stream=True, **(params or {})
        )

    @description("Retrieve the next GID available")
    @returns(int)
    def next_gid(self):
        start_gid, end_gid = self.dispatcher.configstore.get('accounts.local_gid_range')
        gid = None
        for i in range(start_gid, end_gid):
            if not self.datastore.exists('groups', ('gid', '=', i)):
                gid = i
                break

        if not gid:
            raise RpcException(errno.ENOSPC, 'No free GIDs available')

        return gid


@description("Create an user in the system")
@accepts(h.all_of(
    h.ref('User'),
    h.required('username'),
    h.forbidden('builtin'),
    h.object(properties={'password': {'type': ['password', 'null']}}),
    h.any_of(
        h.required('password'),
        h.required('unixhash', 'nthash'),
        h.required('password_disabled')
    )
))
class UserCreateTask(Task):
    def __init__(self, dispatcher):
        super(UserCreateTask, self).__init__(dispatcher)
        self.id = None
        self.created_group = False

    @classmethod
    def early_describe(cls):
        return "Creating user"

    def describe(self, user):
        return TaskDescription("Adding user {name}", name=user['username'])

    def verify(self, user):
        errors = ValidationException()
        normalize_name(user, 'username')

        for code, message in check_unixname(user['username']):
            errors.add((0, 'username'), message, code=code)

        if 'groups' in user and len(user['groups']) > 64:
            errors.add(
                (0, 'groups'),
                'User cannot belong to more than 64 auxiliary groups'
            )

        if user.get('full_name') and ':' in user['full_name']:
            errors.add((0, 'full_name'), 'The character ":" is not allowed')

        if 'email' in user:
            if not EMAIL_REGEX.match(user['email']):
                errors.add(
                    (0, 'email'),
                    "{0} is an invalid email address".format(user['email'])
                )

        if 'home' in user and user['home'] not in (None, '/nonexistent'):
            volumes_root = self.dispatcher.call_sync('volume.get_volumes_root')
            user['home'] = os.path.normpath(user['home'])

            if not user['home'].startswith(volumes_root) or user['home'] == volumes_root:
                errors.add(
                    (0, 'home directory'),
                    "Invalid mountpoint specified for home directory: {0}.\n".format(user['home']) +
                    "Provide a path within zfs pool or dataset mounted under {0}".format(volumes_root)
                )

        if errors:
            raise errors

        return ['system']

    def run(self, user):
        if self.datastore.exists('users', ('username', '=', user['username'])):
            raise TaskException(errno.EEXIST, 'User with given name already exists')

        if 'uid' not in user:
            # Need to get next free UID
            uid = self.dispatcher.call_sync('user.next_uid', user.get('group') is None)
        else:
            uid = user.pop('uid')

        normalize_name(user, 'username')
        normalize(user, {
            'builtin': False,
            'unixhash': None,
            'nthash': None,
            'password_changed_at': None,
            'full_name': 'User &',
            'shell': '/bin/sh',
            'home': '/nonexistent',
            'groups': [],
            'uid': uid,
            'sudo': False,
            'attributes': {}
        })

        if user['home'] is None:
            user['home'] = '/nonexistent'

        if user['home'] != '/nonexistent':
            user['home'] = os.path.normpath(user['home'])
            zfs_dataset_mountpoints = list(self.dispatcher.call_sync('volume.dataset.query', [], {'select': 'mountpoint'}))
            zfs_pool_mountpoints = list(self.dispatcher.call_sync('volume.query', [], {'select': 'mountpoint'}))
            homedir_occurrence = self.dispatcher.call_sync(
                'user.query',
                [('home', '=', user['home'])],
                {'single': True}
            )

            if user['home'] in zfs_pool_mountpoints:
                raise TaskException(
                    errno.ENXIO,
                    'ZFS pool mountpoint cannot be set as the home directory.'
                )

            homedir_mount_path = os.path.join('/', *(user['home'].split(os.path.sep)[:-1]))
            if not any(homedir_mount_path == dataset_mountpoint
                       and os.path.ismount(dataset_mountpoint) for dataset_mountpoint in zfs_dataset_mountpoints):
                raise TaskException(
                    errno.ENXIO,
                    'Home directory has to reside in zfs pool or dataset.' +
                    ' Provide a path which starts with valid, mounted zfs pool or dataset location.'
                )

            if homedir_occurrence:
                raise TaskException(
                    errno.ENXIO,
                    '{} is already assigned to another user.'.format(user['home']) +
                    ' Multiple users cannot share the same home directory.'
                )

        password = user.pop('password', None)
        if password:
            user.update({
                'unixhash': crypted_password(password.secret),
                'nthash': nt_password(password.secret),
                'password_changed_at': datetime.utcnow()
            })

        if user.get('group') is None:
            try:
                result = self.run_subtask_sync('group.create', {
                    'gid': uid,
                    'name': user['username']
                })
            except RpcException as err:
                raise err

            user['group'] = result
            self.created_group = result

        try:
            id = self.datastore.insert('users', user)
            self.id = id
            self.dispatcher.call_sync('etcd.generation.generate_group', 'accounts')
        except SubprocessException as e:
            raise TaskException(
                errno.ENXIO,
                'Could not generate samba password. stdout: {0}\nstderr: {1}'.format(e.out, e.err)
            )
        except DuplicateKeyException as e:
            raise TaskException(errno.EBADMSG, 'Cannot add user: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(
                errno.ENXIO,
                'Cannot regenerate users file: {0}'.format(e)
            )

        if user['home'] != '/nonexistent':
            group = self.dispatcher.call_sync('group.query', [('id', '=', user['group'])], {'single': True})

            if not group:
                raise TaskException(errno.ENOENT, 'Group {0} not found'.format(user['group']))
            user_gid = group['gid']

            if not os.path.exists(user['home']):
                parent_dataset = self.dispatcher.call_sync(
                    'volume.dataset.query',
                    [('mountpoint', '=', homedir_mount_path)],
                    {'single': True}
                )

                homedir_dataset_id = os.path.join(parent_dataset['id'], user['home'].split(os.path.sep)[-1])
                self.run_subtask_sync(
                    'volume.dataset.create',
                    {'id': homedir_dataset_id, 'type': 'FILESYSTEM', 'volume': parent_dataset['volume']}
                )
                os.chmod(user['home'], 0o755)

            else:
                os.chmod(user['home'], 0o755)

            for file in os.listdir(SKEL_PATH):
                if file.startswith('dot'):
                    dest_file = os.path.join(user['home'], file[3:])
                    if not os.path.exists(dest_file):
                        shutil.copyfile(os.path.join(SKEL_PATH, file), dest_file)
                        os.chown(dest_file, uid, user_gid)

                else:
                    dest_file = os.path.join(user['home'], file)
                    if not os.path.exists(dest_file):
                        shutil.copyfile(os.path.join(SKEL_PATH, file), dest_file)
                        os.chown(dest_file, uid, user_gid)

            os.chown(user['home'], uid, user_gid)

        self.dispatcher.dispatch_event('user.changed', {
            'operation': 'create',
            'ids': [id]
        })

        return id

    def rollback(self, user):
        if self.datastore.exists('users', ('id', '=', self.id)):
            self.datastore.delete('users', self.id)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'accounts')

        if self.created_group:
            self.run_subtask_sync('group.delete', self.created_group)


@description("Deletes an user from the system")
@accepts(str, h.ref('UserDelete'))
class UserDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting user"

    def describe(self, id, delete_params=False):
        user = self.datastore.get_by_id('users', id)
        return TaskDescription("Deleting user {name}", name=user['username'] if user else id)

    def verify(self, id, delete_params=False):
        user = self.datastore.get_by_id('users', id)
        if user and user['builtin']:
            raise VerifyException(errno.EPERM, 'Cannot delete builtin user {0}'.format(user['username']))

        return ['system']

    def run(self, id, delete_params=None):
        subtasks = []
        try:
            user = self.datastore.get_by_id('users', id)
            if user is None:
                raise TaskException(errno.ENOENT, 'User with UID {0} does not exist'.format(id))

            if (delete_params and delete_params.get('delete_home_directory') and
                    user['home'] not in (None, '/nonexistent') and os.path.exists(user['home'])):
                homedir_dataset = self.dispatcher.call_sync(
                    'volume.dataset.query',
                    [('mountpoint', '=', user['home'])],
                    {'single': True}
                )
                if homedir_dataset:
                    subtasks.append(self.run_subtask('volume.dataset.delete', homedir_dataset['id']))
            elif user['home'] not in (None, '/nonexistent') and os.path.exists(user['home']):
                self.add_warning(TaskWarning(
                    errno.EBUSY,
                    'Home directory {} left behind, you need to delete it separately'.format(user['home']))
                )

            group = self.datastore.get_by_id('groups', user['group'])
            if group and user['uid'] == group['gid']:
                if delete_params and delete_params.get('delete_own_group'):
                    subtasks.append(self.run_subtask('group.delete', user['group']))

                else:
                    self.add_warning(TaskWarning(
                        errno.EBUSY,
                        'Group {0} ({1}) left behind, you need to delete it separately'.format(group['name'], group['gid']))
                    )

            self.join_subtasks(*subtasks)

            if user.get('smbhash'):
                try:
                    system('/usr/local/bin/pdbedit', '-x', user['username'])
                except SubprocessException as e:
                    pass

            self.datastore.delete('users', id)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'accounts')
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot delete user: {0}'.format(str(e)))

        self.dispatcher.dispatch_event('user.changed', {
            'operation': 'delete',
            'ids': [id]
        })


@description('Updates an user')
@accepts(
    str,
    h.all_of(
        h.ref('User'),
        h.forbidden('builtin')
    )
)
class UserUpdateTask(Task):
    def __init__(self, dispatcher):
        super(UserUpdateTask, self).__init__(dispatcher)
        self.original_user = None

    @classmethod
    def early_describe(cls):
        return "Updating user"

    def describe(self, id, updated_fields):
        user = self.datastore.get_by_id('users', id)
        return TaskDescription("Updating user {name}", name=user['username'] if user else id)

    def verify(self, id, updated_fields):
        errors = ValidationException()
        normalize_name(updated_fields, 'username')

        if updated_fields.get('full_name') and ':' in updated_fields['full_name']:
            errors.add((1, 'full_name'), 'The character ":" is not allowed')

        if 'groups' in updated_fields and len(updated_fields['groups']) > 64:
            errors.add((1, 'groups'), 'User cannot belong to more than 64 auxiliary groups')

        if 'username' in updated_fields:
            for code, message in check_unixname(updated_fields['username']):
                errors.add((1, 'username'), message, code=code)

        if updated_fields.get('email'):
            if not EMAIL_REGEX.match(updated_fields['email']):
                errors.add(
                    (1, 'email'),
                    "{0} is an invalid email address".format(updated_fields['email'])
                )

        if 'home' in updated_fields and updated_fields['home'] not in (None, '/nonexistent'):
            volumes_root = self.dispatcher.call_sync('volume.get_volumes_root')
            updated_fields['home'] = os.path.normpath(updated_fields['home'])
            if not updated_fields['home'].startswith(volumes_root) or updated_fields['home'] == volumes_root:
                errors.add(
                    (1, 'home directory'),
                    "Invalid mountpoint specified for home directory: {0}.\n".format(updated_fields['home']) +
                    "Provide a path within zfs pool or dataset mounted under {0}".format(volumes_root)
                )

        if errors:
            raise errors

        return ['system']

    def run(self, id, updated_fields):
        normalize_name(updated_fields, 'username')

        user = self.datastore.get_by_id('users', id)
        self.original_user = copy.deepcopy(user)
        if user is None:
            raise TaskException(
                errno.ENOENT, "User with id: {0} does not exist".format(id)
            )

        if user.get('builtin'):
            if 'home' in updated_fields:
                raise TaskException(
                    errno.EPERM, "Cannot change builtin user's home directory"
                )

            # Similarly ignore uid changes for builtin users
            if 'uid' in updated_fields:
                raise TaskException(errno.EPERM, "Cannot change builtin user's UID")

            if 'username' in updated_fields:
                raise TaskException(
                    errno.EPERM, "Cannot change builtin user's username"
                )

            if 'locked' in updated_fields:
                raise TaskException(
                    errno.EPERM, "Cannot change builtin user's locked flag"
                )

        if not user:
            raise TaskException(errno.ENOENT, 'User {0} not found'.format(id))

        if 'home' in updated_fields and updated_fields['home'] is None:
            updated_fields['home'] = '/nonexistent'

        if 'home' in updated_fields and updated_fields['home'] != '/nonexistent':
            updated_fields['home'] = os.path.normpath(updated_fields['home'])
            zfs_dataset_mountpoints = list(self.dispatcher.call_sync('volume.dataset.query', [], {'select': 'mountpoint'}))
            zfs_pool_mountpoints = list(self.dispatcher.call_sync('volume.query', [], {'select': 'mountpoint'}))
            homedir_occurrence = self.dispatcher.call_sync(
                'user.query',
                [('home', '=', updated_fields['home'])],
                {'single': True}
            )
            homedir_mount_path = os.path.join('/', *(updated_fields['home'].split(os.path.sep)[:-1]))

            user_gid = self.datastore.get_by_id('groups', user['group'])
            user_gid = user_gid['gid'] if user_gid else 0

            if user['home'] != updated_fields['home']:

                if updated_fields['home'] in zfs_pool_mountpoints:
                    raise TaskException(
                        errno.ENXIO,
                        'Volume mountpoint cannot be set as the home directory.'
                    )

                if not any(homedir_mount_path == dataset_mountpoint
                           and os.path.ismount(dataset_mountpoint) for dataset_mountpoint in zfs_dataset_mountpoints):
                    raise TaskException(
                        errno.ENXIO,
                        'Home directory has to reside in zfs pool or dataset.' +
                        ' Provide a path which starts with valid, mounted zfs pool or dataset location.'
                    )

                if homedir_occurrence:
                    raise TaskException(
                        errno.ENXIO,
                        '{} is already assigned to another user.'.format(updated_fields['home']) +
                        ' Multiple users cannot share the same home directory.'
                    )

                if not os.path.exists(updated_fields['home']):
                    parent_dataset = self.dispatcher.call_sync(
                        'volume.dataset.query',
                        [('mountpoint', '=', homedir_mount_path)],
                        {'single': True}
                    )

                    homedir_dataset_id = os.path.join(
                        parent_dataset['id'],
                        updated_fields['home'].split(os.path.sep)[-1]
                    )

                    self.run_subtask_sync(
                        'volume.dataset.create',
                        {'id': homedir_dataset_id, 'type': 'FILESYSTEM', 'volume': parent_dataset['volume']}
                    )
                    os.chmod(updated_fields['home'], 0o755)

                else:
                    os.chmod(updated_fields['home'], 0o755)

                for file in os.listdir(SKEL_PATH):
                    if file.startswith('dot'):
                        dest_file = os.path.join(updated_fields['home'], file[3:])
                        if not os.path.exists(dest_file):
                            shutil.copyfile(os.path.join(SKEL_PATH, file), dest_file)
                            os.chown(dest_file, user['uid'], user_gid)

                    else:
                        dest_file = os.path.join(updated_fields['home'], file)
                        if not os.path.exists(dest_file):
                            shutil.copyfile(os.path.join(SKEL_PATH, file), dest_file)
                            os.chown(dest_file, user['uid'], user_gid)

                os.chown(updated_fields['home'], user['uid'], user_gid)

        user.update(updated_fields)

        try:
            password = user.pop('password', None)
            if password:
                user.update({
                    'unixhash': crypted_password(password.secret),
                    'nthash': nt_password(password.secret),
                    'password_changed_at': datetime.utcnow()
                })

            self.datastore.update('users', user['id'], user)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'accounts')
        except SubprocessException as e:
            raise TaskException(
                errno.ENXIO,
                'Could not generate samba password. stdout: {0}\nstderr: {1}'.format(e.out, e.err))
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot update user: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(e.code, 'Cannot regenerate users file: {0}'.format(e.message))

        self.dispatcher.dispatch_event('user.changed', {
            'operation': 'update',
            'ids': [user['id']]
        })

    def rollback(self, uid, updated_fields):
        user = self.original_user
        self.datastore.update('users', uid, user)
        self.dispatcher.call_sync('etcd.generation.generate_group', 'accounts')


@description("Creates a group")
@accepts(h.all_of(
    h.ref('Group'),
    h.required('name'),
    h.forbidden('builtin')
))
class GroupCreateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Creating group"

    def describe(self, group):
        return TaskDescription("Adding group {name}", name=group['name'])

    def verify(self, group):
        errors = ValidationException()
        normalize_name(group, 'name')

        for code, message in check_unixname(group['name']):
            errors.add((0, 'name'), message, code=code)

        if errors:
            raise errors

        return ['system']

    def run(self, group):
        if self.datastore.exists('groups', ('name', '=', group['name'])):
            raise TaskException(
                errno.EEXIST,
                'Group {0} already exists'.format(group['name'])
            )

        if 'gid' in group and self.datastore.exists('groups', ('gid', '=', group['gid'])):
            raise TaskException(
                errno.EEXIST,
                'Group with GID {0} already exists'.format(group['gid'])
            )

        if 'gid' not in group:
            # Need to get next free GID
            gid = self.dispatcher.call_sync('group.next_gid')
        else:
            gid = group.pop('gid')

        try:
            normalize_name(group, 'name')
            group['builtin'] = False
            group['gid'] = gid
            group.setdefault('sudo', False)
            gid = self.datastore.insert('groups', group)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'accounts')
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot add group: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(e.code, 'Cannot regenerate groups file: {0}'.format(e.message))

        self.dispatcher.dispatch_event('group.changed', {
            'operation': 'create',
            'ids': [gid]
        })

        return gid


@description("Updates a group")
@accepts(
    str,
    h.all_of(
        h.ref('Group'),
        h.forbidden('builtin')
    )
)
class GroupUpdateTask(Task):
    @classmethod
    def early_describe(cls):
        return "Updating group"

    def describe(self, id, updated_fields):
        group = self.datastore.get_by_id('groups', id)
        return TaskDescription("Updating group {name}", name=group['name'] if group else id)

    def verify(self, id, updated_fields):
        errors = ValidationException()
        normalize_name(updated_fields, 'name')

        if 'name' in updated_fields:
            for code, message in check_unixname(updated_fields['name']):
                errors.add((1, 'name'), message, code=code)

        if errors:
            raise errors

        return ['system']

    def run(self, id, updated_fields):
        if 'name' in updated_fields:
            if self.datastore.exists('groups', ('name', '=', updated_fields['name']), ('id', '!=', id)):
                raise TaskException(
                    errno.EEXIST,
                    'Group {0} already exists'.format(updated_fields['name'])
                )

        try:
            normalize_name(updated_fields, 'name')
            group = self.datastore.get_by_id('groups', id)
            if group is None:
                raise TaskException(errno.ENOENT, 'Group {0} does not exist'.format(id))

            group.update(updated_fields)
            self.datastore.update('groups', id, group)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'accounts')
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot update group: {0}'.format(str(e)))
        except RpcException as e:
            raise TaskException(e.code, 'Cannot regenerate groups file: {0}'.format(e.message))

        self.dispatcher.dispatch_event('group.changed', {
            'operation': 'update',
            'ids': [id]
        })


@description("Deletes a group")
@accepts(str)
class GroupDeleteTask(Task):
    @classmethod
    def early_describe(cls):
        return "Deleting group"

    def describe(self, id):
        group = self.datastore.get_by_id('groups', id)
        return TaskDescription("Deleting group {name}", name=group['name'] if group else id)

    def verify(self, id):
        # Check if group exists
        group = self.datastore.get_by_id('groups', id)

        if group and group['builtin'] is True:
            raise VerifyException(
                errno.EINVAL, 'Group {0} is built-in and can not be deleted'.format(group['name']))

        return ['system']

    def run(self, id):
        try:
            group = self.datastore.get_by_id('groups', id)
            if group is None:
                raise TaskException(errno.ENOENT, 'Group with given ID does not exist')

            # Remove group from users
            for i in self.datastore.query_stream('users', ('groups', 'in', group['gid'])):
                i['groups'].remove(id)
                self.datastore.update('users', i['id'], i)

            self.datastore.delete('groups', id)
            self.dispatcher.call_sync('etcd.generation.generate_group', 'accounts')
        except DatastoreException as e:
            raise TaskException(errno.EBADMSG, 'Cannot delete group: {0}'.format(str(e)))

        self.dispatcher.dispatch_event('group.changed', {
            'operation': 'delete',
            'ids': [id]
        })


def collect_debug(dispatcher):
    yield AttachFile('passwd', '/etc/passwd.json')
    yield AttachFile('group', '/etc/group.json')


def _init(dispatcher, plugin):
    # Register definitions for objects used
    plugin.register_schema_definition('User', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'sid': {'type': ['string', 'null'], 'readOnly': True},
            'uid': {
                'type': 'integer',
                'minimum': 0,
                'maximum': 4294967295
            },
            'gid': {'type': 'string', 'readOnly': True},
            'builtin': {'type': 'boolean', 'readOnly': True},
            'username': {'type': 'string'},
            'full_name': {'type': ['string', 'null']},
            'email': {
                'oneOf': [
                    {'$ref': 'Email'},
                    {'type': 'null'}
                ]
            },
            'locked': {'type': 'boolean'},
            'sudo': {'type': 'boolean'},
            'password_disabled': {'type': 'boolean'},
            'password_changed_at': {'type': ['datetime', 'null']},
            'group': {'type': ['string', 'null']},
            'shell': {'type': 'string'},
            'home': {'type': ['string', 'null']},
            'password': {'type': ['password', 'null']},
            'unixhash': {'type': ['string', 'null']},
            'lmhash': {'type': ['string', 'null']},
            'nthash': {'type': ['string', 'null']},
            'sshpubkey': {'type': ['string', 'null']},
            'attributes': {'type': 'object'},
            'groups': {
                'type': 'array',
                'items': {
                    'type': 'string'
                }
            },
            'origin': {
                'type': 'object',
                'properties': {
                    'directory': {'type': 'string'},
                    'cached_at': {'type': ['datetime', 'null']},
                    'ttl': {'type': ['number', 'null']},
                    'read_only': {'type': 'boolean'}
                }
            }
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('Group', {
        'type': 'object',
        'properties': {
            'id': {'type': 'string'},
            'sid': {'type': ['string', 'null'], 'readOnly': True},
            'gid': {
                'type': 'integer',
                'minimum': 0,
                'maximum': 4294967295
            },
            'builtin': {'type': 'boolean', 'readOnly': True},
            'name': {'type': 'string'},
            'sudo': {'type': 'boolean'},
            'members': {
                'type': 'array',
                'readOnly': True,
                'items': {'type': 'string'}
            },
            'origin': {
                'type': 'object',
                'properties': {
                    'directory': {'type': 'string'},
                    'cached_at': {'type': ['datetime', 'null']},
                    'ttl': {'type': ['number', 'null']},
                    'read_only': {'type': 'boolean'}
                }
            }
        },
        'additionalProperties': False,
    })

    plugin.register_schema_definition('UserDelete', {
        'type': 'object',
        'additionalProperties': False,
        'properties': {
            'delete_own_group': {'type': 'boolean'},
            'delete_home_directory': {'type': 'boolean'},
        }
    })

    # Register provider for querying accounts and groups data
    plugin.register_provider('user', UserProvider)
    plugin.register_provider('group', GroupProvider)

    # Register task handlers
    plugin.register_task_handler('user.create', UserCreateTask)
    plugin.register_task_handler('user.update', UserUpdateTask)
    plugin.register_task_handler('user.delete', UserDeleteTask)
    plugin.register_task_handler('group.create', GroupCreateTask)
    plugin.register_task_handler('group.update', GroupUpdateTask)
    plugin.register_task_handler('group.delete', GroupDeleteTask)

    # Register event types
    plugin.register_event_type('user.changed')
    plugin.register_event_type('group.changed')

    # Register debug hook
    plugin.register_debug_hook(collect_debug)
