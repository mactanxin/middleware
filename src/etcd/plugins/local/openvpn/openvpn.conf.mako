<%
    import os

    OPENVPN_DIR = '/etc/local/openvpn'
    openvpn_conf = dispatcher.call_sync('service.openvpn.get_config')

    if not os.path.isdir(OPENVPN_DIR):
        os.mkdir(OPENVPN_DIR)

    if openvpn_conf['mode'] == 'pki':
        for cert in ['ca', 'key', 'cert']:
            cert_data = dispatcher.call_sync('crypto.certificate.query',
                                            [('id', '=', openvpn_conf[cert])], {'single': True})
            if cert != 'key':
                openvpn_conf[cert] = cert_data['certificate_path']
            else:
                openvpn_conf[cert] = cert_data['privatekey_path']

%>\
% if openvpn_conf['mode'] == 'pki':
dev ${openvpn_conf['dev']}
% if openvpn_conf['dev'] == 'tun':
topology subnet
% endif
server ${openvpn_conf['server_ip']} ${openvpn_conf['server_netmask']}
% if openvpn_conf['persist_key']:
persist-key
% endif
% if openvpn_conf['persist_tun']:
persist-tun
% endif
ca ${openvpn_conf['ca']}
cert ${openvpn_conf['cert']}
key ${openvpn_conf['key']}
dh /usr/local/etc/openvpn/dh.pem
% if openvpn_conf['tls_auth']:
tls-auth /usr/local/etc/openvpn/ta.key 0
% endif
cipher ${openvpn_conf['cipher']}
max-clients ${openvpn_conf['max_clients']}
user ${openvpn_conf['user']}
group ${openvpn_conf['group']}
port ${openvpn_conf['port']}
proto ${openvpn_conf['proto']}
% if openvpn_conf['comp_lzo']:
comp-lzo
% endif
% for route in openvpn_conf['push_routes']:
push "route ${route}"
% endfor
verb ${openvpn_conf['verb']}
% if openvpn_conf['auxiliary']:
${openvpn_conf['auxiliary']}
% endif

% else:
secret /usr/local/etc/openvpn/ta.key
dev ${openvpn_conf['dev']}
ifconfig ${openvpn_conf['psk_server_ip']} ${openvpn_conf['psk_remote_ip']}
port ${openvpn_conf['port']}
% endif
