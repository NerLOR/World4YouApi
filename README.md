
# World4YouApi
This is a simple Python API for the DNS provider [World4You](https://www.world4you.com/).
It can be used to automatically update your dynamic IP Address.

## World4YouApi.py
Here you can find the ```World4YouApi``` class. 

### Functions
* ##### ```login(username, password)```
    Log in to your Account 

* ##### ```get_resource_records()```
    Download and save all resource records

* ##### ```add(resource_name, dns_type, value)```
    Add a resource record.
    * ```resource_name``` is the name of the entry
    * ```dns_type``` is the record type (A, AAAA, CNAME, TXT, ...)
    * ```value``` is the 

* ##### ```update(resource_name, value)```
    Update a resource record.
    * ```resource_name``` is the name of the entry
    * ```value``` is the 

* ##### ```alter(resource_name, dns_type, value)```
    Alter a resource record.
    * ```resource_name``` is the name of the entry
    * ```dns_type``` is the record type (A, AAAA, CNAME, TXT, ...)
    * ```value``` is the 

* ##### ```delete(resource_name)```
    Delete a resource record.
    * ```resource_name``` is the name of the entry
    
## world4you
