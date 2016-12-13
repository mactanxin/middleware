<%
    ups = dispatcher.call_sync('service.ups.get_config')
%>\
% if ups['allow_remote_connections']:
LISTEN 0.0.0.0
% else:
LISTEN 127.0.0.1
% endif
