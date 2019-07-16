
# World4YouApi
This is a simple Python API for the DNS provider [World4You](https://www.world4you.com/).
It can be used to automatically update your dynamic IP Address.

## world4you
This Python script can be executed to update manipulate the resource records 
from command line.

```world4you [-i] [-q] -u username [{-p pwd | -P file}] [{-f | -F}] [action [arg ...]]```

**HINT:** If no password or file is provided, the password is read from ```stdin```. 

**HINT:** If the provided *FQDN-Type-Value* combination is not unique, the script will not be able to update the resource record (see ```-f``` and ```-F```).

* ```-i```, ```--interactive``` Interactive mode
* ```-q```, ```--quiet``` Quiet Mode, do not output logging messages
* ```-u```, ```--username``` Username for World4You
* ```-p pwd```, ```--password pwd``` Password as plain text
* ```-P file```, ```--password-file file``` The first line of the given file is used as password 
* ```-f```, ```--force-one``` If the provided *FQDN-Type-Value* combination is **not unique**, perform the specified action on **exactly one** matching resource record
* ```-F```, ```--force-all``` If the provided *FQDN-Type-Value* combination is **not unique**, perform the specified action on **all** matching resource records
* ```action``` The action to be performed. Possible values: 
    * ```add <fqdn> <dns-type> <value>```
    * ```update {<id> | <fqdn> [<dns-type> [<old-value>]]} <new-value>```
    * ```alter {<id> | <fqdn> [<old-dns-type> [<old-value>]]} <new-dns-type> [<new-value>]```
    * ```delete {<id> | <fqdn> [<dns-type> [<value>]]}```
    * ```table```
    * ```csv```

## acme.sh integration
To integrate this api to acme.sh see [here](https://github.com/NerLOR/World4YouApi/tree/master/acme.sh).
