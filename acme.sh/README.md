
# acme.sh API integration
If you want to use this api in dns validations via ```acme.sh``` just copy or 
link ```w4yapi.sh``` to your ```acme.sh/dnsapi/``` folder.
The next step is to ```export W4Y_USERNAME='name'``` and ```export W4Y_PASSWORD='pwd'```. 
Once the script has finished the first run, the username and password will be saved by acme.sh.

```
export W4Y_USERNAME='name'
export W4Y_PASSWORD='pwd'
acme.sh --issue -d example.com --dns dns_w4yapi
```

For further information see [acme.sh Documentation](https://github.com/Neilpang/acme.sh/wiki/DNS-API-Dev-Guide)

