---
title: Preparation before analysing Cobalt Strike.
author: cotes
date: 2021-08-12 12:13:00 +0800
categories: [Hunter, CobaltStrike]
tags: []
pin: false
math: true
mermaid: true
image:
  path: /assets/img/preparation_before_analysing_CobaltStrike/cs.png
---

## Preface


Cobalt Strike is a modular attack framework that is popular with red team and penetration testers due to its ease of use and scalability.And today we will discuss the preparations before analyzing Cobalt Strike. There are two main points: decompiling and packet capture


## Decompiling


As we all know, CobaltStrike is a commercial software and there seems to be no way to get an officially licensed version except by purchasing it. However, I have found that some security researchers upload their CobaltStrike to publicly available threat intelligence platforms. It is therefore possible to obtain CobaltStrike from these platforms, but it is important to be safe, as these tools are not secured accordingly.


You can now refer to the following three links for sample CobaltStrike.


* https://verify.cobaltstrike.com/
* https://www.virustotal.com/gui/file/c3c243e6218f7fbaaefb916943f500722644ec396cf91f31a30c777c2d559465/detection
* https://s.threatbook.cn/report/file/02fa5afe9e58cb633328314b279762a03894df6b54c0129e8a979afcfca83d51/?sign=history&env=win10\_1903\_enx64\_office2016


![](/assets/img/preparation_before_analysing_CobaltStrike/001.png)
![](/assets/img/preparation_before_analysing_CobaltStrike/002.png)
![](/assets/img/preparation_before_analysing_CobaltStrike/003.png)

OK, let’s start the decompilation.

![](/assets/img/preparation_before_analysing_CobaltStrike/004.png)

Idea comes with a decompiler plugin `java-decompiler.jar`

* https://www.codenong.com/cs108912277/
* https://stackoverflow.com/questions/28389006/how-to-decompile-to-java-files-intellij-idea


![](/assets/img/preparation_before_analysing_CobaltStrike/005.png)


```
java -cp java-decompiler.jar org.jetbrains.java.decompiler.main.decompiler.ConsoleDecompiler -dgs=true cobaltstrike.jar code/

```

The original bytecode can be easily decompiled into java code using this decompiler tool. A jar package will be generated when the execution is complete.

```shell
~/P/J/C/code ❯❯❯ ls -alh
总用量 20M
drwxrwxr-x 2 elloit elloit 4.0K 8月  13 15:31 ./
drwxrwxr-x 4 elloit elloit 4.0K 8月  13 15:37 ../
-rw-rw-r-- 1 elloit elloit  20M 8月  13 15:40 cobaltstrike.jar

```
Next we create a project to develop it twice.

![](/assets/img/preparation_before_analysing_CobaltStrike/006.png)

![](/assets/img/preparation_before_analysing_CobaltStrike/007.png)

![](/assets/img/preparation_before_analysing_CobaltStrike/008.png)

![](/assets/img/preparation_before_analysing_CobaltStrike/009.png)

![](/assets/img/preparation_before_analysing_CobaltStrike/010.png)

![](/assets/img/preparation_before_analysing_CobaltStrike/011.png)

Recompile and run it.
![](/assets/img/preparation_before_analysing_CobaltStrike/012.png)

## TLS Packet capture

The communication between Beacon or CobaltStrike and TeamServer is encrypted via TLS and we want to know the communication faults, we have to capture the traffic, which can be easily done with the following tool.

https://github.com/neykov/extract-tls-secrets

```
java -XX:ParallelGCThreads=4 -XX:+AggressiveHeap -XX:+UseParallelGC -Xms512M -Xmx1024M -javaagent:extract-tls-secrets-4.0.0.jar=/tmp/secrets.log -jar cobaltstrike.jar

```
![](/assets/img/preparation_before_analysing_CobaltStrike/013.png)

![](/assets/img/preparation_before_analysing_CobaltStrike/014.png)

## Reference

* https://verify.cobaltstrike.com/
* https://www.virustotal.com/gui/file/c3c243e6218f7fbaaefb916943f500722644ec396cf91f31a30c777c2d559465/detection
* https://s.threatbook.cn/report/file/02fa5afe9e58cb633328314b279762a03894df6b54c0129e8a979afcfca83d51/?sign=history&env=win10\_1903\_enx64\_office2016
* https://stackoverflow.com/questions/28389006/how-to-decompile-to-java-files-intellij-idea
* https://www.codenong.com/cs108912277/
* https://github.com/neykov/extract-tls-secrets
