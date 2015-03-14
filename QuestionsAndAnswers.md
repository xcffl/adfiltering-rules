# 1.黑名单和白名单有何区别？ #
答：黑名单是广告过滤规则，而白名单是由于规则过滤不当而导致某些网站无法正常显示的临时解决方法。
# 2.平时发布的是黑名单还是白名单？我怎么分辨？ #
答：黑名单的文件名基本都有标注“rules\_for”或无特殊标识；白名单会明确标明是白名单，规则文件名有“whitelist”字样。为了便捷，[部分黑名单中就有包含白名单](https://code.google.com/p/adfiltering-rules/wiki/WhiteList)。
# 3.能否发布规则的时候发布黑名单和白名单一起发布？ #
答：部分是可以的。有些广告过滤软件是将白名单和黑名单放在同一个文件中，这样导入导出非常方便。而有的则[不是这样](https://code.google.com/p/adfiltering-rules/wiki/WhiteList)，因为它们的白名单与黑名单导入地方不同，因此无法添加至同一文件。注意，**请勿将白名单导入至黑名单**，否则将无法正常显示很多网页。白名单与黑名单导入地方不同，因此无法添加至同一文件。
# 4.如果更新规则，我需要做什么操作吗？是全新导入呢？还是在基础上导入啊？我是在原来的基础上导入的，有影响吗？ #
答：每个广告过滤软件的操作都不同，可以点此查看详细。导入时一定要**全新导入**，如果是要替换文件，一定要关闭占有此文件的程序，并关闭它们的自我保护。如果不这样，可能有以下影响：
**可能同一规则会有多条；** 新版本取出的误过滤规则不会去除而导致误过滤；
**文件被占用导致导入失败；** 文件正在操作中，文件内容被篡改导致乱码等后果以致规则失效或错误。_因此务必全新导入。_
# 5.有一个网站使用你的规则发生了显示不正常/无法访问问题，或还是会出现广告，怎么办？ #
到[这里](https://code.google.com/p/adfiltering-rules/issues/entry?template=%E5%8F%8D%E9%A6%88%E9%97%AE%E9%A2%98)反馈即可。
# 6.目前支持的广告过滤软件列表 #
### 已知支持以下几个软件（某些未列出但是仍可使用）： ###
![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/360.png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/360.png)
![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/AB_Pro.png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/AB_Pro.png)
![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/ABP.png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/ABP.png)
![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/Avast.png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/Avast.png)
![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/genera.png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/genera.png)
![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/Kingsoft.png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/Kingsoft.png)
![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/Opera.png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/Opera.png)
![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/TPL(IE9+).png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/TPL(IE9+).png)
# 7.如何导入规则？ #
### 请点击以下对应过滤软件图标查看： ###
### [![](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/Kingsoft.png)](http://bbs.duba.net/forum.php?mod=redirect&goto=findpost&ptid=22647779&pid=7019336) ###
### ![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/ABP.png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/ABP.png) =====>见[规则获取页面](http://xcffl.tk/adfilter/getit/) ###
### [![](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/360.png)](http://bbs.kafan.cn/forum.php?mod=viewthread&tid=821042&page=137&extra=#pid18771972) ###
### [![](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/genera.png)](http://bbs.kafan.cn/forum.php?mod=viewthread&tid=821042&page=6&extra=#pid15515054) ###
### [![](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/Opera.png)](http://bbs.kafan.cn/forum.php?mod=viewthread&tid=821042&page=135#pid18722226) ###
### ![https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/TPL(IE9+).png](https://adfiltering-rules.googlecode.com/svn/wiki/images/%E5%9B%BE%E6%A0%87/small/TPL(IE9+).png) =====>见[规则获取页面](http://xcffl.tk/adfilter/getit/) ###