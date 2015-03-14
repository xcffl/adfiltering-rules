## 广告过滤规则 ##
### 若更新适用于所有规则 ###
将修改手工转换成ABP格式，即：
  * `||ad.somesite.com/*`
  * `*.somesites.com/*`
然后更新至 _rules\_for\_ABP.txt_ 中。最后，运行onekey.exe，待程序结束后，提交。
### 若仅适用于TPL或urlfilter.ini ###
将修改添加到 _extra.dat_ 的相应位置。然后运行onekey.exe，待程序结束后，提交。



## 元素隐藏规则 ##
针对所有 _custom.css_ 中的规则。
### 如果是通用规则 ###
可直接复制到 _rules\_for\_ABP.txt_ 中，然后运行onekey.exe，提交。
### 如果可以限域 ###
`能限域尽量限域，避免误过滤。`
以如下格式修改到 _rules\_for\_ABP.txt_ 相应网站分类中：
> `sites.com##.ad`
其中的 _##.ad_ 即 _custom.css_ 中的原规则，无需修改。仅 _sites.com_ 作为限定域名。
最后运行onekey.exe，提交。