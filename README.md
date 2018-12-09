
# World4YouApi
This is a simple Python API for the DNS provider [World4You](https://www.world4you.com/).
It can be used to automatically update your dynamic IP Address.

## world4you
This Python script can be executed to update manipulate the resource records 
from command line.

```world4you [-i] [-q] -u username [-p pwd] [-P file] [action [arg ...]]```
* ```-i```, ```--interactive``` Interactive mode
* ```-q```, ```--quiet``` Quiet Mode, do not output logging messages
* ```-u```, ```--username``` Username for World4You
* ```-p pwd```, ```--password pwd``` Password as plain text
* ```-P file```, ```--password-file file``` The first line of the given file is used as password  
If no password or file is proveded, the password is read from ```stdin```.
* ```action``` The action to be performed. Possible values: 
    * ```add <fqdn> <dns-type> <value>```
    * ```update <fqdn> <value>```
    * ```alter <fqdn> <dns-type> <value>```
    * ```delete <fqdn>```
    * ```table```
    * ```csv```

## World4YouApi.py
Here you can find the ```World4YouApi``` class. 

### Functions
* ```login(username, password)```
Log in to your Account 

* ```get_resource_records()```
    Download and save all resource records

* ```add(resource_name, dns_type, value)```
    Add a resource record.
    * ```resource_name``` is the name of the entry
    * ```dns_type``` is the record type (A, AAAA, CNAME, TXT, ...)
    * ```value``` is the 

* ```update(resource_name, value)```
    Update a resource record.
    * ```resource_name``` is the name of the entry
    * ```value``` is the 

* ```alter(resource_name, dns_type, value)```
    Alter a resource record.
    * ```resource_name``` is the name of the entry
    * ```dns_type``` is the record type (A, AAAA, CNAME, TXT, ...)
    * ```value``` is the 

* ```delete(resource_name)```
    Delete a resource record.
    * ```resource_name``` is the name of the entry

