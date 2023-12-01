---
title: TLS server-side tagging using JARM fingerprinting (chinese)
author: cotes
date: 2020-12-14 12:13:00 +0800
categories: [Hunter, Jarm]
tags: []
pin: false
math: true
mermaid: true
image:
  path: /assets/img/honeypot/0.1.jpg
---


Attention
=========


This article was written while I was in the [360 Quake Team](https://quake.360.cn/quake/#/index). Copyright © qihoo 360.


0x01 背景
-------


**对网络空间测绘数据的分析和发掘**，是Quake团队一直以来的核心目标。


十几年来Web应用的飞速发展使其毋庸置疑的成为了互联网的主流。为了弥补Web应用和HTTP协议的各类安全问题，HTTP over SSL/TLS在互联网中的比例也逐年提升。因此，对全网SSL/TLS相关测绘与数据分析一直是Quake系统关注的重点之一。


当前Quake系统**已经支持任意端口、任意协议使用的SSL/TLS证书提取、分析、握手包的解析与留存**。


注册用户在`证书`窗口中就可以看到TLS证书按照x509格式进行解析后的内容，同时 **付费会员（高级会员、终身会员、企业会员）**可以在 `tls协议` 窗口中看到完整的TLS握手过程，并提供格式化解析后的数据，在 `server_certificates` 中就包含了对服务端证书的指纹采集计算。如下图所示：


![]()


![]()


与此同时，我们也在持续关注TLS主动测绘方向的前沿研究。近期，我们留意到有关研究人员在发布了一篇名为[Easily Identify Malicious Servers on the Internet with JARM](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a)的文章，并在github上发布了一个[JARM扫描工具](https://github.com/salesforce/jarm)，相关内容引起了国外部分研究人员的讨论。在Quake团队小伙伴一致努力下，现已将此功能集成入Quake系统。


经过一段时间的分析研究，我们也总结出一些关于JARM的认识与大家交流和分享。抛砖引玉，希望大家多多指正。


0x02 JARM介绍
-----------


JARM 是一个**主动式**TLS服务端指纹工具，主要用途如下：


1. 快速验证一组TLS服务器是否使用相同的TLS配置；
2. 通过TLS配置划分TLS服务器，并识别可能归属的公司；
3. 识别网站默认的应用或基础架构；
4. 识别恶意软件C&C控制节点，以及其他恶意服务器。


### 2.1 JARM工作原理


想要理解JARM工作原理，必须要了解TLS工作的流程，这里就不再详细讲解，我们用一句话简单概括下TLS握手的大致目的：客户端和服务端双方基于彼此的配置进行沟通、协商和校验，在达成一致后生成密钥。而JARM的核心在于：**TLS Server根据TLS Client Hello中参数的不同，返回不同的Server Hello数据包。而Client Hello的参数可以人为指定修改，因此通过发送多个精心构造的Client Hello获取其对应的特殊Server Hello，最终形成TLS Server的指纹（有点类似于Fuzz的感觉）。** 具体能够产生影响的参数包括但不限于：


* 操作系统及其版本
* OpenSSL等第三方库及其版本
* 第三方库的调用顺序
* 用户自定义配置
* ……


### 2.2 JARM工作流程


JARM通过主动向TLS服务器发送10个TLS Hello数据包并对Server Hello中的特定字段进行分析，以特定方式对10个TLS服务器响应进行哈希处理，最终生成JARM指纹。


JARM中的10个TLS客户端Hello数据包经过特殊设计，目的就是提取TLS服务器中的唯一响应。例如：


* JARM以不同的顺序发送不同的TLS版本，密码和扩展；
* TLS Clint将密码从最弱到最强排序，TLS Server将选择哪种密码？
* ……


总之JARM与我们在进行流量分析威胁时常用的JA3、JA3/S不同：


* JA3、JA3/S主要基于流量
* JARM则是完全主动的扫描并生成指纹


因此有了上述的理论基础，我们尝试分析JARM工具的具体代码。


### 2.3 JARM工具代码分析


首先在main函数，jarm定义了10种TLS Client Hello数据包生成的结构，分别包含了待扫描的目标、端口、tls客户端加密套件、TLS扩展列表：


![]()


然后依次遍历这10种TLS Client Hello结构生成数据包，并使用packet\_building函数生成对应的TLS Client Hello数据包，然后依次发送数据包：


![]()


通过send\_packet发送数据包以后，使用read\_packet解析返回TLS Server Hello，并拼接为如下格式：


![]()


字段含义：




`|  |  |
| --- | --- |
|
```
1

```
| 
```
服务器返回的加密套件 | 服务器返回选择使用的TLS协议版本 |  TLS扩展ALPN协议信息 | TLS扩展列表

```
 |`
通过发送10次TLS Client Hello并解析为以上格式，将10次解析的结果拼接以后最终调用jarm\_hash算出最终的结果。


jarm\_hash前30个字符由加密套件和TLS协议版本分别使用cipher\_bytes、version\_byte函数计算拼接而来，其余的32个字符是由TLS扩展ALPN协议信息和TLS扩展列表通过sha256哈希并截取而来：


![]()


0x03 JARM的应用与问题
---------------


### 3.1 利用JARM搜寻服务端


通过上述对JARM的研究我们理解了JARM的原理。因此将JARM集成进入了Quake底层识别引擎Vscan的协议深度识别流程之中。


其实在我们之前的文章[浅析 CobaltStrike Beacon 扫描](https://quake.360.cn/quake/#/reportDetail?id=5fc63af88bba0dde0bfa8b2d])中，有心的小伙伴已经留意到了在某些支持SSL/TLS的端口 `端口响应` 标签文本末尾有一串形如“JARM:xxxxxxxxxxxxxxx”的字符串，这便是该端口的JARM指纹。Quake搜索语法如下，注意替换`JARM:`之后的内容：




`|  |  |
| --- | --- |
| 
```
1

```
 | 
```
response:"JARM:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"

```
 |`
现目前Quake**注册用户**就能够在`端口响应` 文本的末尾看到其JARM指纹。**该内容为系统自动追加后的数据，并不是该端口原始返回数据，请注意区分**。


![]()


同时，所有 **终身会员、企业会员** 能够查看`TLS-JARM`协议深度识别的内容：


![]()


经过一段持续测绘后，我们发现了一些有趣的现象，下面让我们一起看看。


### 3.2 利用JARM识别C2与问题


在[Easily Identify Malicious Servers on the Internet with JARM](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a)原文中，作者给出了一份C2和JARM对应的清单，这里我们就不赘述了。


![]()


当我们得到这些C2和JARM的时候是十分高兴的，因为在理想情况下如果JARM与C2唯一对应，那么我们就多了一种主动发现C2节点的特征。可是事与愿违，搜索上面的那个CS对应的JARM: `response:"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"`


![]()


我们发现数量不少，独立IP有2338个。但是 TOP5的应用为：




| 应用 | 数量 |
| --- | --- |
| Cobalt Strike团队服务器 | 1,137 |
| CobaltStrike-Beacon服务端 | 373 |
| Tomcat-Web服务器 | 40 |
| Weblogic应用服务器 | 21 |
| WordPressCMS博客系统 | 14 |


可以看到和上面CobaltStrike相同JARM的还有 Tomcat、Weblogic和WordPress等开启TLS的Web应用，也就是说CobaltStrike这个应用只是该JARM对应TLS服务器其中的一个子集。


继续在本地搭建环境进行测试，Cobalt Strike 4.0 在JDK 11.0.9.1下 JARM为 `07d2ad16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1`。


![]()


在Quake中搜索： `response:"CobaltStrike Beacon configurations" AND response:"07d2ad16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"`，发现没有CobaltStrike Beacon为这个JARM。


![]()


回到本地环境切换JDK版本，同一个Cobalt Strike 4.0，在JDK 1.8.0\_212情况下JARM为：`07d2ad16d21d21d07c07d2ad07d21d9b2f5869a6985368a9dec764186a9175`。


![]()


看来JARM似乎和CobaltStrike无关，为了证明这一点，在相同JDK环境下搭建Tomcat服务配置TLS。结果如下：


JDK 11.0.9.1 Tomcat 9.0.41 JARM `07d2ad16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1`


JDK 1.8.0\_212 Tomcat 9.0.41 JARM `07d2ad16d21d21d07c07d2ad07d21d9b2f5869a6985368a9dec764186a9175`


发现JARM分别和CobaltStrike在两个JDK环境下的一样，看来这个和CobaltStrike不是强关联性的，也解释了为什么会有那么多的Weblogic和Tomcat应用被识别出来了。


进一步对多个JDK版本进行测试得到如下结果：


![]()


![]()


![]()


看来，我们并不能直接通过JARM去判定CobaltStrike；同样，对于CobaltStrike而言JARM也并不唯一，其JARM与不同JDK环境下TLS服务有关。


JARM只能作为一个辅助手段，结合之前CobaltStrike的特征，我们提取了部分CobaltStrike服务器的JARM数据放置在Quake的开源仓库中，仅供业界研究使用（不作为精准威胁情报）：[CobaltStrike-JARM](https://github.com/360quake/CobaltStrike-JARM)


![]()


0x04 结论与思考
----------


JARM其实对识别CobaltStrike等上层应用软件并不十分可靠，仅仅能够起到一个辅助的作用，实际工作中还是要结合多方面的信息来进行判断。


但是，也不是说JARM完全没有作用，JARM的本质是对TLS服务进行标记，例如：我们可以结合已知的JDK版本对应的JARM可以看到公网上运行在特定版本JDK环境下的服务，如图为运行在JDK 11.0.9.1的ELasticSearch，运行在JDK 11.05的Weblogic。


![]()


![]()


JARM仅仅是一种TLS服务端特征的标识方式， `不能完全被用作Web上层应用的唯一指纹` 。


总归来说，JARM提供的思路大于其本身价值：利用主动测绘的方式，向目标发送各类数据包，根据不同的返回进而发掘、分析、提取目标特征。


正如在[A Red Teamer Plays with JARM](https://blog.cobaltstrike.com/2020/12/08/a-red-teamer-plays-with-jarm/)中提到的：



> 
> This is a commoditized threat intelligence practice. If your blue team uses this type of information, there are a lot of options to protect your infrastructure.
> 
> 
> 



> 
> 基于主动测绘的威胁情报正在各个方向落地生根。通过对主动测绘数据各个维度的统计、分析信息，能够提供新的防护思路。
> 
> 
> 


Happy hunting by using 360-Quake.


0x05 参考文章
---------


* https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a
* https://github.com/salesforce/jarm
* https://blog.cobaltstrike.com/2020/12/08/a-red-teamer-plays-with-jarm/


