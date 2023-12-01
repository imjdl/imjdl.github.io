---
title: Artica Web Proxy 4.30 Authentication Bypass & OS Command Injection
author: cotes
date: 2020-08-09 12:13:00 +0800
categories: [vulnerability, Artica]
tags: []
pin: false
math: true
mermaid: true
image:
  path: /assets/img/artica_proxy/logo.png
---


## Vendor:

www.articatech.com

## Product:

Artica Web Proxy v4.30.000000

Download: http://www.articatech.com/download.php

> *Proxy Cache and Web filtering Appliance
Artica Proxy is a system that provide a sexy Web Ajax console in order manage a full Proxy server without any technical skill and with latest Squid technology.
It provide surls filtering with french Toulouse University and Artica database - over 30.000.000 websites.
There are many statistics per users or categories or websites and features in order to manage Internet bandwith.
It provides FireWall/QOS features.
Can work in Transparent mode or connected to an Activ Directory/OpenLDAP members database.


## Authentication Bypass (CVE-2020-17506)

Artica provides an API interface in `fw.login.php` for authentication. The parameter `apikey` has a SQL injection vulnerability, an attacker can forge a `$_SESSION["uid"]` by co-injection to log in any user. In the code, `$_SESSION["uid"] == "-100"` indicates that the current user is `SuperAdmin`.

![](/assets/img/artica_proxy/api.png)

The next step is to construct a local array to commit to.
![](/assets/img/artica_proxy/content.png)

`https://172.16.237.222:9000/fw.login.php?apikey=%27UNION%20select%201,%27YToyOntzOjM6InVpZCI7czo0OiItMTAwIjtzOjIyOiJBQ1RJVkVfRElSRUNUT1JZX0lOREVYIjtzOjE6IjEiO30=%27;`

![](/assets/img/artica_proxy/2020-08-11-13-44.gif)

## OS Command Injection (CVE-2020-17505)

After successfully bypassing authentication to get admin access, I tried this to find out more about the problem that allowed me to get root access.Where `cyurs.index.php` is loaded with `cyurs.php` and the unchecked parameter `service_cmds_peform` is passed into the `service_cmds` function and called.

![](/assets/img/artica_proxy/image-20200811134828979.png)


![](/assets/img/artica_proxy/image-20200811134948165.png)


payload: `https://172.16.237.222:9000/cyrus.index.php?service-cmds-peform=||whoami||`


Eventually I managed to execute the command with root privileges.


![](/assets/img/artica_proxy/2020-08-11-13-53.gif)


## Reference


* https://cwe.mitre.org/data/definitions/78.html
* https://cwe.mitre.org/data/definitions/592.html

## TimeLine

* 2020-08-08: Vulnerability found and submitted to vendor with no response.
* 2020-08-12: Submitted to CVE.
* 2020-08-13: CVE Confirms Vulnerability.


