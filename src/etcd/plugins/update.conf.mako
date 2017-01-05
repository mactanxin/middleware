[Defaults]
update_server = ${"internal" if config.get("update.internal") else "default"}
[internal]
name = Internal Update Server
url = http://update-int.ixsystems.com/FreeNAS/
signing = False
