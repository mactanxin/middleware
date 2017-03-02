<%
    default_realm = dispatcher.call_sync('kerberos.realm.get_default_realm')
%>
[appdefaults]
    pam = {
        forwardable = true
        ticket_lifetime = 86400
        renew_lifetime = 86400
    }

[libdefaults]
    dns_lookup_realm = true
    dns_lookup_kdc = true
    kdc_timesync = true
    ticket_lifetime = 24h
    clockskew = 300
    forwardable = yes
% if default_realm:
    default_realm = ${default_realm}
% endif

[domain_realm]
% for realm in dispatcher.call_sync('kerberos.realm.query'):
	${realm['realm']} = ${realm['realm'].upper()}
	.${realm['realm']} = ${realm['realm'].upper()}
	${realm['realm'].upper()} = ${realm['realm'].upper()}
	.${realm['realm'].upper()} = ${realm['realm'].upper()}
% endfor

[realms]
% for realm in dispatcher.call_sync('kerberos.realm.query'):
	${realm['realm']} = {
        % if realm.get('kdc_address'):
            kdc = ${realm['kdc_address']}
        % endif
        % if realm.get('admin_server_address'):
            admin_server = ${realm['admin_server_address']}
        % endif
	}
% endfor

[logging]
	default = SYSLOG:INFO:LOCAL7

