
# World4YouApi

This is a simple Python API for the DNS provider [World4You](https://www.world4you.com/).
It may be used to automatically update your dynamic IP Address or to automatically renew 
your certificates using [acme.sh](https://github.com/acmesh-official/acme.sh) with the ```--dns``` option.
And yes, wildcard certificates are possible!


## acme.sh integration

Part of this API is used in [acme.sh](https://github.com/NerLOR/acme.sh).


## world4you

This Python script may be executed to update and manipulate the resource records 
from command line.

```
world4you [-i] [-q] -u USERNAME [-p PWD | -P FILE] [-f | -F] [ACTION [ARG ...]]
```

**HINT:** If no password or file is provided, the password is read from `stdin`.

**HINT:** If the provided *FQDN-Type-Value* combination is not unique, the script will not be able to perform the specified action on the resource record (see `-f` and `-F`).

* `-i`, `--interactive` Interactive mode
* `-q`, `--quiet` Quiet Mode, do not output logging messages
* `-u`, `--username` Username for World4You
* `-p pwd`, `--password pwd` Password as plain text
* `-P file`, `--password-file file` The first line of the given file is used as password
* `-f`, `--force-one` If the provided *FQDN-Type-Value* combination is **not unique**, perform the specified action on **exactly one** matching resource record
* `-F`, `--force-all` If the provided *FQDN-Type-Value* combination is **not unique**, perform the specified action on **all** matching resource records
* `action` The action to be performed. Possible values:
    * `add <fqdn> <dns-type> <value>`
    * `update <fqdn> [<dns-type> [<old-value>]] <new-value>`
    * `alter <fqdn> <old-dns-type> <old-value> <new-dns-type> [<new-value>]`
    * `delete <fqdn> [<dns-type> [<value>]]`
    * `table [full] [<domain> ...]`
    * `csv [<domain> ...]`
