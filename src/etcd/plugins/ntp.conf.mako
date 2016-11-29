% for ntp in dispatcher.call_sync('ntp_server.query'):
% if ntp.get('pool'):
pool\
% else:
server\
% endif
 ${ntp['address']}\
% if ntp.get('burst'):
 burst\
% endif
% if ntp.get('iburst'):
 iburst\
% endif
% if ntp.get('prefer'):
 prefer\
% endif
% if ntp.get('maxpoll') is not None:
 maxpoll ${ntp['maxpoll']}\
% endif
% if ntp.get('minpoll') is not None:
 minpoll ${ntp['minpoll']}\
% endif

% endfor
restrict -4 default limited kod nomodify notrap nopeer noquery
restrict -6 default limited kod nomodify notrap nopeer noquery
restrict source notrap nomodify noquery
restrict 127.0.0.1
restrict ::1
restrict 127.127.1.0
