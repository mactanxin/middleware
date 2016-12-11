<%
    from bsd import sysctl
    from freenas.utils.permissions import perm_to_oct_string

    adv_config = dispatcher.call_sync('system.advanced.get_config')
    gen_config = dispatcher.call_sync('system.general.get_config')
    lldp_config = dispatcher.call_sync('service.lldp.get_config')
    smartd_config = dispatcher.call_sync('service.smartd.get_config')
    tftp_config = dispatcher.call_sync('service.tftpd.get_config')
    ups_config = dispatcher.call_sync('service.ups.get_config')

    hwmodel = sysctl.sysctlbyname("hw.model")

    nfs_config = dispatcher.call_sync('service.nfs.get_config')
    nfs_ips = ' '.join(['-h {0}'.format(ip) for ip in (nfs_config['bind_addresses'] or [])])
%>\
hostname="${gen_config["hostname"]}"
local_startup="/usr/local/etc/rc.d"
early_late_divider="*"
root_rw_mount="YES"
clear_tmpX="NO"
background_fsck="NO"
fsck_y_enable="YES"
synchronous_dhclient="YES"
zfs_enable="YES"
devd_enable="NO"

# middleware10
dispatcher_enable="YES"
dispatcher_flags="--log-level=DEBUG --log-file=/var/log/dispatcher.log --load-disabled False"
datastore_enable="YES"
datastore_dbdir="/data"
datastore_driver="mongodb"
etcd_enable="YES"
etcd_flags="-c /usr/local/etc/middleware.conf /etc"
networkd_enable="YES"
dscached_enable="YES"
fnstatd_enable="YES"
schedulerd_enable="YES"
containerd_enable="YES"
alertd_enable="YES"
crashd_enable="YES"
debugd_enable="YES"
neighbord_enable="YES"
clid_enable="YES"
restd_enable="YES"
syslogd_enable="NO"
syslog_ng_enable="YES"
# turbo boost
performance_cpu_freq="HIGH"

devfs_system_ruleset="usbrules"

# open-vm-tools
vmware_guest_vmblock_enable="YES"
vmware_guest_vmhgfs_enable="YES"
vmware_guest_vmmemctl_enable="YES"
vmware_guest_vmxnet_enable="YES"
vmware_guestd_enable="YES"

# Do not mark to autodetach otherwise ZFS get very unhappy
geli_autodetach="NO"

# A set of storage supporting kernel modules, they must be loaded before ix-fstab.
early_kld_list="geom_stripe geom_raid3 geom_raid5 geom_gate geom_multipath"

# A set of kernel modules that can be loaded after mounting local filesystems.
kld_list="dtraceall ipmi fuse"

gateway_enable="YES"
ipv6_activate_all_interfaces="YES"
rtsold_enable="YES"
dbus_enable="YES"
mdnsd_enable="YES"
nginx_enable="YES"

# AppCafe related services
syscache_enable="YES"
appcafe_enable="YES"

ataidle_enable="YES"
vboxnet_enable="YES"
watchdogd_enable="NO"

collectd_enable="YES"
ntpd_enable="YES"
ntpd_sync_on_start="YES"

ctld_flags="-u"

# Selectively enable services for now
% for svc in ds.query("service_definitions", ('name', 'in', ['afp', 'ctl', 'ftp', 'glusterd', 'lldp', 'rsyncd', 'smartd', 'snmp', 'sshd', 'tftpd', 'webdav', 'iscsid'])):
    % if config.get("service.{0}.enable".format(svc["name"])):
${svc['rcng']['rc-scripts']}_enable="YES"
    % else:
${svc['rcng']['rc-scripts']}_enable="NO"
    % endif
% endfor

% if config.get("service.smb.enable"):
samba_server_enable="YES"
##% if ! dirsrv_enabled domaincontroller
smbd_enable="YES"
nmbd_enable="YES"
winbindd_enable="YES"
##% endif
% endif
% if config.get("service.dyndns.enable"):
inadynmt_enable="YES"
% endif

% if config.get("service.ipfs.enable"):
ipfs_go_enable="YES"
% endif
ipfs_go_path="${config.get("service.ipfs.path")}"

ladvd_flags="-a\
% if lldp_config['save_description']:
 -z\
% endif
% if lldp_config['country_code']:
 -c ${lldp_config['country_code']}\
% endif
% if lldp_config['location']:
 -l \"${lldp_config['location']}\"\
% endif
"

% if nfs_config['enable']:
%  if nfs_config['v4']:
nfsv4_server_enable="YES"
%  else:
nfsv4_server_enable="NO"
%  endif
rpcbind_enable="YES"
nfs_server_enable="YES"
rpc_lockd_enable="YES"
rpc_statd_enable="YES"
mountd_enable="YES"
nfsd_enable="YES"
nfsuserd_enable="YES"
gssd_enable="YES"
% endif

nfs_server_flags="-t -n ${nfs_config['servers']} ${nfs_ips}\
% if nfs_config['udp']:
 -u\
% endif
"
mountd_flags="-l -rS ${nfs_ips}\
% if nfs_config['nonroot']:
 -n\
% endif
% if nfs_config['mountd_port']:
 -p ${nfs_config['mountd_port']}\
% endif
"
rpc_statd_flags="${nfs_ips}\
% if nfs_config['rpcstatd_port']:
 -p ${nfs_config['rpcstatd_port']}\
% endif
"
rpc_lockd_flags="${nfs_ips}\
% if nfs_config['rpclockd_port']:
 -p ${nfs_config['rpclockd_port']}\
% endif
"
% if nfs_ips:
rpcbind_flags="${nfs_ips}"
% endif

% if smartd_config['interval']:
smartd_flags="-i ${smartd_config['interval']*60}"
% endif

snmpd_conffile="/usr/local/etc/snmpd.conf"
snmpd_flags="-Ls5d"

tftpd_flags="-s -u ${tftp_config['username']} -U ${perm_to_oct_string(tftp_config['umask'])}\
% if tftp_config['port'] != 69:
 -a :${tftp_config['port']}\
% endif
% if tftp_config['allow_new_files']:
 -c\
% endif
% if tftp_config['auxiliary']:
 ${tftp_config['auxiliary']}\
% endif
% if tftp_config['path']:
 ${tftp_config['path']}\
% endif
"

% if ups_config['mode'] == 'MASTER' and ups_config['enable']:
nut_enable="YES"
nut_upslog_ups="${ups_config['identifier']}"
% elif ups_config['mode'] == 'SLAVE' and ups_config['enable']:
nut_upslog_ups="${ups_config['identifier']}@${ups_config['remote_host']}:${ups_config['remote_port']}"
% endif
% if ups_config['enable']:
nut_upslog_enable="YES"
nut_upsmon_enable="YES"
% endif

% if gen_config['console_keymap']:
keymap="${gen_config['console_keymap']}"
% endif

% for ctl in dispatcher.call_sync('tunable.query', [('type', '=', 'RC')]):
% if ctl.get('enabled', True):
${ctl['var']}="${ctl['value']}"
% endif
% endfor

% if adv_config.get('console_screensaver'):
saver="daemon"
% endif

# Get crashdumps
dumpdev="AUTO"
dumpdir="/data/crash"
savecore_flags="-z -m 5"
% if adv_config.get('uploadcrash'):
ix_diagnose_enable="YES"
% endif

% if adv_config.get('powerd'):
powerd_enable="YES"
% endif

% if config.get("service.openvpn.enable"):
openvpn_enable="YES"
openvpn_configfile="/usr/local/etc/openvpn/openvpn.conf"
% endif

% if config.get("service.consul.enable"):
consul_enable="YES"
% endif
