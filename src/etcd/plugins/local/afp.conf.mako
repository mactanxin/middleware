<%
    from freenas.utils.permissions import perm_to_oct_string

    afp = dispatcher.call_sync('service.afp.get_config')

    uam_list = ['uams_dhx.so', 'uams_dhx2.so']
    if afp['guest_enable']:
        uam_list.append('uams_guest.so')

    def norm_users(users, groups):
        if groups:
            groups = ['@' + group for group in groups]
        return (users if users else []) + (groups if groups else [])

    def get_permissions(perms):
        if perms:
            return "0" + perm_to_oct_string(perms)
%>\
<%def name="opt(name, val)">\
% if val:
% if type(val) is list:
    ${name} = ${", ".join(val)}
% else:
    ${name} = ${val}
% endif
% endif
</%def>\
\
[Global]
    uam list = ${' '.join(uam_list)}
% if afp['guest_user']:
    guest account = ${afp['guest_user']}
% endif
% if not afp['bind_addresses']:
    afp listen = 0.0.0.0
% else:
    afp listen = ${' '.join(afp['bind_addresses'])}
% endif
    max connections = ${afp['connections_limit']}
    mimic model = RackMac
% if afp['dbpath']:
    vol dbnest = no
    vol dbpath = ${afp['dbpath']}
% else:
    vol dbnest = yes
% endif
% if afp['auxiliary']:
    ${afp['auxiliary']}
% endif

% if afp['homedir_enable']:
[Homes]
    basedir regex = ${afp['homedir_path']}
%   if afp['homedir_name']:
    home name = ${afp['homedir_name']}
%   endif
% endif

% for share in dispatcher.call_sync("share.query", [("type", "=", "afp"), ("enabled", "=", True)]):
[${share["name"]}]
${opt("path", share["filesystem_path"])}\
${opt("valid users", norm_users(share["properties"].get("users_allow"), share["properties"].get("groups_allow")))}\
${opt("invalid users", norm_users(share["properties"].get("users_deny"), share["properties"].get("groups_deny")))}\
${opt("hosts allow", share["properties"].get("hosts_allow"))}\
${opt("hosts deny", share["properties"].get("hosts_deny"))}\
${opt("rolist", norm_users(share["properties"].get("ro_users"), share["properties"].get("ro_groups")))}\
${opt("rwlist", norm_users(share["properties"].get("rw_users"), share["properties"].get("rw_groups")))}\
${opt("time machine", "yes" if share["properties"].get("time_machine") else "no")}\
${opt("read only", "yes" if share["properties"].get("read_only") else "no")}\
${opt("cnid dev", "no" if share["properties"].get("zero_dev_numbers") else "yes")}\
${opt("stat vol", "no" if share["properties"].get("no_stat") else "yes")}\
${opt("unix priv", "yes" if share["properties"].get("afp3_privileges") else "no")}\
${opt("file perm", get_permissions(share["properties"].get("default_file_perms")))}\
${opt("directory perm", get_permissions(share["properties"].get("default_directory_perms")))}\
${opt("umask", get_permissions(share["properties"].get("default_umask")))}\
${opt("veto files", ".windows/.mac/")}
% endfor
