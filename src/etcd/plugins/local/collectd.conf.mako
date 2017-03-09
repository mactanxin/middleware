FQDNLookup false
BaseDir "/var/db/collectd"
PIDFile "/var/run/collectd.pid"
PluginDir "/usr/local/lib/collectd"

LoadPlugin aggregation
LoadPlugin cpu
LoadPlugin cputemp
LoadPlugin interface
LoadPlugin load
LoadPlugin memory
LoadPlugin network
LoadPlugin nfsstat
LoadPlugin processes
LoadPlugin swap
LoadPlugin uptime
LoadPlugin syslog
LoadPlugin geom_stat
LoadPlugin zfs_arc
LoadPlugin zfs_arc_v2
LoadPlugin unixsock
LoadPlugin write_graphite

<Plugin "syslog">
    LogLevel err
</Plugin>

<Plugin "aggregation">
    <Aggregation>
        Plugin "cpu"
        Type "cpu"
        GroupBy "Host"
        GroupBy "TypeInstance"
        CalculateSum true
    </Aggregation>
</Plugin>

<Plugin "interface">
    Interface "lo0"
    Interface "plip0"
    Interface "/^usbus/"
    IgnoreSelected true
</Plugin>

<Plugin "geom_stat">
    Filter "^([a]?da|ciss|md|mfi|mfid|md|nvd|xbd|vtbd|multipath/mpath)[0123456789]+(\.eli)?$"
</Plugin>

<Plugin "zfs_arc">
</Plugin>

<Plugin unixsock>
    SocketFile "/var/run/collectd.sock"
    SocketGroup "collectd"
    SocketPerms "0770"
</Plugin>

<Plugin "write_graphite">
    <Node "freenas">
        Host "127.0.0.1"
        Port "2003"
        StoreRates true
        AlwaysAppendDS true
    </Node>
    % for i in config.get('system.graphite_servers'):
        <Node "graphite_${loop.index}">
            Host "${i}"
            Port "2003"
            Protocol "tcp"
            EscapeCharacter "_"
            LogSendErrors true
            StoreRates true
            AlwaysAppendDS true
        </Node>
    % endfor
</Plugin>

<LoadPlugin python>
    Globals true
</LoadPlugin>

<Plugin python>
    ModulePath "/usr/local/lib/fnstatd/plugins"
    LogTraces true
    Interactive false
    Import "collectd-zfs"
    Import "collectd-disktemp"

    <Module "collectd-zfs">
    </Module>
    <Module "collectd-disktemp">
    </Module>
</Plugin>
