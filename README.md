# AWS

## SSO.py

**sso.py** is a library used to gather information from all the AWS account assigned, and it is the replacement of **SSOTest.py**
1. To use this script your IAM role must have set the privileges necessaries to list account in your sso directory and to request temporary credentials. 
2. It is necessary the creation of the access token using the AWS cli option 
```cmd
    aws configure sso
```

## getsubscriptions.py

This script is a basic use of the library, and gather the list of accounts id with the account name (subscription name). 

## SAAS and PAAS services.py

The script retrieve information of the buckets and WAF deployed in each account.

## WAF.py

It is a bit more complex script that retrieves the information of all Web Application Firewall (**WAF**) deployed in each account and each region. Also, gather the information of the ELBv2 attached to the WAF and some configuration, like the ports open, and the SSL Policy attached in those ports.

For this script is necessary to install the [progress library](https://github.com/verigak/progress)

```python3
python3 -m pip install progress

```


## **All the scripts were tested in Windows 10**
