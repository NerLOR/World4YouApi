
# acme.sh API integration
If you want to use this api in dns validations via ```acme.sh``` just copy 
```w4yapi.sh``` to your ```acme.sh/dnsapi/``` folder and __change ```$SCRIPTPATH``` to the path
where your repository is located__.
The next step is to ```export W4Y_USERNAME='name'``` and ```export W4Y_PASSWORD='pwd'```. 
Once the script has finished the first run, the username and password will be saved by acme.sh.

```
cp ./World4YouApi/acme.sh/dns_w4y.sh /[...]/acme.sh/dnsapi/
nano /[...]/acme.sh/dnsapi/dns_w4y.sh  # Change $SCRIPTPATH
export W4Y_USERNAME='name'
export W4Y_PASSWORD='pwd'
acme.sh --issue -d example.com --dns dns_w4yapi
```

For further information see [acme.sh Documentation](https://github.com/Neilpang/acme.sh/wiki/DNS-API-Dev-Guide).

