<%
    config = dispatcher.call_sync('service.nfs.get_config')

    def unique_networks():
        for s in dispatcher.call_sync("share.query", [("type", "=", "nfs"), ("enabled", "=", True)]):
            if not s['properties'].get('hosts'):
                yield s, None
                continue

            for h in s['properties']['hosts']:
                yield s, h

    def opts(share, network):
        if not 'properties' in share:
            return ''
        result = []
        properties = share['properties']
        if properties.get('alldirs'):
            result.append('-alldirs')
        if properties.get('read_only'):
            result.append('-ro')
        if properties.get('security'):
            result.append('-sec={0}'.format(':'.join(properties['security'])))
        if properties.get('mapall_user'):
            if properties.get('mapall_group'):
                result.append('-mapall={mapall_user}:{mapall_group}'.format(**properties))
            else:
                result.append('-mapall={mapall_user}'.format(**properties))
        elif properties.get('maproot_user'):
            if properties.get('maproot_group'):
                result.append('-maproot={maproot_user}:{maproot_group}'.format(**properties))
            else:
                result.append('-maproot={maproot_user}'.format(**properties))

        if network:
            if '/' in network:
                result.append('-network={0}'.format(network))
            else:
                result.append(network)

        return ' '.join(result)
%>\
% if config.get('v4'):
% if config.get('v4_kerberos'):
V4: / -sec=krb5:krb5i:krb5p
% else:
V4: / -sec=sys:krb5:krb5i:krb5p
% endif
% endif
% for share, network in unique_networks():
${share["filesystem_path"]} ${opts(share, network)}
% endfor