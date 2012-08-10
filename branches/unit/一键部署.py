# -*- coding: utf-8 -*-

#===ABP===
# -*- coding: utf-8 -*-
#毕业于2012.08.06 v1.0
#增加自动获取时间功能 2012.08.07 v1.1
#精简到仅仅更新时间。 2012。08.10 v1.2


#先定义原规则各部分，再过滤出chinalist中新规则，分别按顺序打印到文件，再复制回来
import re, os
import time

#读取afr，合并到同一字符串
afrfile = open('rules_for_ABP.txt', 'r')
afr = afrfile.readlines()
afr = ''.join(afr)



#更新“更新时间”
time = time.strftime("%Y-%m-%d %X", time.localtime())
afr = re.sub(r'(?<=!Updated:).*', time ,afr)
afrfile.close()
afrfile = open('rules_for_ABP.txt', 'w')
print >> afrfile, afr
afrfile.close()

#===猎豹版===
#!/usr/bin/env python
# coding: utf-8

# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/


import sys, os, re, subprocess, urllib2, time, traceback, codecs, hashlib, base64
from getopt import getopt, GetoptError

acceptedExtensions = {
  '.txt': True,
}
ignore = {
  'rules_for_KSafe.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Plus_Rules.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
  'rules_for_360.txt': True,
  'rules_for_ESET[1].txt': True,
  'rules_for_ESET[2].txt': True,
  'rules_for_Kaspersky.txt': True,
  
}
verbatim = {
  'COPYING': True,
}

def combineSubscriptions(sourceDir, targetDir, timeout=30):
  global acceptedExtensions, ignore, verbatim

  if not os.path.exists(targetDir):
    os.makedirs(targetDir, 0755)

  known = {}
  for file in os.listdir(sourceDir):
    if file in ignore or file[0] == '.' or not os.path.isfile(os.path.join(sourceDir, file)):
      continue
    if file in verbatim:
      processVerbatimFile(sourceDir, targetDir, file)
    elif not os.path.splitext(file)[1] in acceptedExtensions:
      continue
    else:
      try:
        processSubscriptionFile(sourceDir, targetDir, file, timeout)
      except:
        print >>sys.stderr, '错误处理订阅文件 "%s"' % file
        traceback.print_exc()
        print >>sys.stderr
      known['rules_for_liebao.txt'] = True
    known[file] = True


  for file in os.listdir(targetDir):
    if file[0] == '.':
      continue
    if not file in known:
      os.remove(os.path.join(targetDir, file))

def conditionalWrite(filePath, data):
  changed = True
  if os.path.exists(filePath):
    handle = codecs.open(filePath, 'rb', encoding='utf-8')
    oldData = handle.read()
    handle.close()

    checksumRegExp = re.compile(r'^.*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n', re.M | re.I)
    oldData = re.sub(checksumRegExp, '', oldData)
    oldData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', oldData)
    newData = re.sub(checksumRegExp, '', data)
    newData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', newData)
    if oldData == newData:
      changed = False
  if changed:
    handle = codecs.open(filePath, 'wb', encoding='utf-8')
    handle.write(data)
    handle.close()
    

def processVerbatimFile(sourceDir, targetDir, file):
  handle = codecs.open(os.path.join(sourceDir, file), 'rb', encoding='utf-8')
  conditionalWrite(os.path.join(targetDir, file), handle.read())
  handle.close()

def processSubscriptionFile(sourceDir, targetDir, file, timeout):
  filePath = os.path.join(sourceDir, file)
  handle = codecs.open(filePath, 'rb', encoding='utf-8')
  lines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
  handle.close()

  header = ''
  if len(lines) > 0:
    header = lines[0]
    del lines[0]
  if not re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', header, re.I):
    raise Exception('这是不是一个有效的Adblock Plus的订阅文件。')

  lines = resolveIncludes(filePath, lines, timeout)
  lines = filter(lambda l: l != '' and not re.search(r'!\s*checksum[\s\-:]+([\w\+\/=]+)', l, re.I), lines)

  writeRule(os.path.join(targetDir, 'rules_for_liebao.txt'), lines)

  checksum = hashlib.md5()
  checksum.update((header + '\n' + '\n'.join(lines) + '\n').encode('utf-8'))
  lines.insert(0, '! Checksum: %s' % re.sub(r'=', '', base64.b64encode(checksum.digest())))
  lines.insert(0, header)
  conditionalWrite(os.path.join(targetDir, file), '\n'.join(lines) + '\n')

def resolveIncludes(filePath, lines, timeout, level=0):
  if level > 5:
    raise Exception('有太多的嵌套包含，这可能是循环引用的地方。')


  result = []
  for line in lines:
    match = re.search(r'^\s*%include\s+(.*)%\s*$', line)
    if match:
      file = match.group(1)
      newLines = None
      if re.match(r'^https?://', file):
        result.append('! *** Fetched from: %s ***' % file)


        request = urllib2.urlopen(file, None, timeout)
        charset = 'utf-8'
        contentType = request.headers.get('content-type', '')
        if contentType.find('charset=') >= 0:
          charset = contentType.split('charset=', 1)[1]
        newLines = unicode(request.read(), charset).split('\n')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), newLines)
        newLines = filter(lambda l: not re.search(r'^\s*!.*?\bExpires\s*(?::|after)\s*(\d+)\s*(h)?', l, re.M | re.I), newLines)
      else:
        result.append('! *** %s ***' % file)

        parentDir = os.path.dirname(filePath)
        includePath = os.path.join(parentDir, file)
        relPath = os.path.relpath(includePath, parentDir)
        if len(relPath) == 0 or relPath[0] == '.':
          raise Exception('无效包括 "%s", 需要是一个 HTTP/HTTPS 地址或一个相对文件路径' % file)

        handle = codecs.open(includePath, 'rb', encoding='utf-8')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
        newLines = resolveIncludes(includePath, newLines, timeout, level + 1)
        handle.close()
        
      '''if re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        line = re.sub(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]','![Liebao Adblock Rule]', line)
        result.append('[Liebao Adblock Rule]')'''

	  
        

     
      if len(newLines) and re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        del newLines[0]
      result.extend(newLines)
    else:
      if line.find('%timestamp%') >= 0:
        if level == 0:
          line = line.replace('%timestamp%', time.strftime('%d %b %Y %H:%M UTC', time.gmtime()))
        else:
          line = ''
      result.append(line)
  return result

def writeRule(filePath, lines):
  result = []
  top = u'![Liebao Adblock Rule]'
  result.append(top)
  lines[6] = ''
  for line in lines:
    if re.search(r'^!', line):
      #把各种注释内容替换掉
      #line = re.sub(r'(#|!)\-+[^\-]*$','', line)
      line = re.sub(r'(.*?)\expires(.*)', '', line)
      line = re.sub('!Title:.*$', '!Title:adfiltering-rules', line)
      #由于猎豹有些问题，暂时使用短名称
      #line = re.sub('for ABP', 'for liebao', line)
      line = re.sub(r'--!$', '--!', line)
      line = re.sub(u'!Description:一个通用、全面的广告过滤规则', u'''!Version:1.0
!Description:一个通用、全面的广告过滤规则/
!Url:https://adfiltering-rules.googlecode.com/svn/trunk/lastest/rules_for_liebao.txt''', line)
      result.append(line)
    elif line.find('#') >= 0:
      # 如果是元素隐藏规则
      #猎豹浏览器暂不支持domain~的排除规则，删掉排除
      line = re.sub(r',~[^,#]+(?=#)', '', line)
      line = re.sub(r'^~[^,]+,', '', line)
      line = re.sub(r'^~[^,#]+(?=#)', '', line)     
      #没域名的全局规则直接添加      
      if re.search(r'^###', line):
        result.append(line)
      elif re.search(r'^##', line):
        result.append(line)
        
            
      #有域名的调转域名位置
      elif re.search(r'.+###', line):
        
        l = line.split('###')
        for line in l:

          dm = l[0]
          eh = l[1]
 
        
        
          
        #多个域名的就分割掉
        if re.search(r'(?<=[^,]),(?=[^,])', dm):
          
          cut = dm.split(',')
          times = len(cut)         
          

          if times == 2:
            for dm in cut:
              dm1 = cut[0]
              dm2 = cut[1]

            
            line = '''###%s	$d=%s\n###%s	$d=%s''' %(eh,dm1,eh,dm2)
            

          
          if times == 4:
            for dm in cut:
              dm1 = cut[0]
              dm2 = cut[1]
              dm3 = cut[2]
              dm4 = cut[3]
            line = '''##%s	$d=%s
##%s	$d=%s
##%s	$d=%s
##%s	$d=%s''' %(eh,dm1,eh,dm2,eh,dm3,eh,dm4)
            
          #else:
            #print '====n1====\n' + line
        else:
          line = '##%s	$d=%s' %(eh,dm)
        result.append(line)
      #两个#的话
      elif re.search(r'.+##', line):
        l = line.split('##')
        for line in l:
          dm = l[0]
          eh = l[1]
        #多个域名分割掉
        if re.search(r'(?<=[^,]),(?=[^,])', dm):
          cut = dm.split(',')
          times = len(cut)          
          if times == 2:
            for dm in cut:
              dm1 = cut[0]
              dm2 = cut[1]
            #生成多行
            line = '''##%s	$d=%s
##%s	$d=%s''' %(eh,dm1,eh,dm2)
            
            
          if times == 4:
            for dm in cut:
              dm1 = cut[0]
              dm2 = cut[1]
              dm3 = cut[2]
              dm4 = cut[3]
            line = '''##%s	$d=%s
##%s	$d=%s
##%s	$d=%s
##%s	$d=%s''' %(eh,dm1,eh,dm2,eh,dm3,eh,dm4)
          #else:
            #print '====n2====\n' + line
        else:
          line = '##%s	$d=%s' %(eh,dm)
          
        result.append(line)




    else:
      # 有一个阻挡或例外规则，尝试将其转换
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = line[2:]
        

      hasUnsupportedOptions = False
      requiresScript = False
      match = re.search(r'^(.*?)\$(.*)', line)
      if match:
        # 此规则有规则作用选项，检查他们是否是重要的
        line = match.group(1)
        options = match.group(2).replace('_', '-').lower().split(',')

        # 一些选项在IE浏览器不支持，但可以放心地忽略，删除它们
        options = filter(lambda o: not o in ('', 'third-party', '~third-party', 'match-case', '~match-case', '~object-subrequest', '~other', '~donottrack'), options)

        # 同时忽视白名单的否定规则
        if isException:
          options = filter(lambda o: not o.startswith('domain=~'), options)

        if 'donottrack' in options:
          # 不要跟踪选项的规则应始终被删除
          hasUnsupportedOptions = True
          
        unsupportedOptions = 0
        
        if 'object-subrequest' in options:
          # 该规则适用于对象的子请求，无法过滤
          unsupportedOptions += 1

        if 'elemhide' in options:
          # 元素隐藏排除规则不支持
          unsupportedOptions += 1
          
        if unsupportedOptions >= len(options):
          # 该规则只适用于不支持的选项
          hasUnsupportedOptions = True
        else:
          # 规则有其他需要进行评估的重要选项
          if 'script' in options and (len(options) - unsupportedOptions) == 1:
            # 过滤类型选项只适用于近似转换脚本
            requiresScript = True
          else:
            # 不支持该规则的进一步选项
            # 除非是特定于域的一个例外规则，所有剩余的选项将被忽略，以避免潜在的误报。
           if isException:
              hasUnsupportedOptions = any([o.startswith('domain=') for o in options])
           elif re.search('@@', origLine):
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:        
        # 包括不支持的选项的过滤器（即包含domain的过滤规则)
        #猎豹浏览器暂不支持domain~的排除规则，删掉排除
        origLine = re.sub(r'\|~[^|]+(?=\|)', '', origLine)
        origLine = re.sub(r'\|~[^|]+$', '', origLine)
        origLine = re.sub(r'\$domain=~[^|]+$', '', origLine)
        
        origLine = re.sub(r'^@@\|\*', '', origLine)
        origLine = re.sub(r'^\|\*', '', origLine)
        origLine = re.sub(r'\/', '\/', origLine)        
        origLine = re.sub(r'^@@\/', '', origLine)
        origLine = re.sub(r'\*\|$', '$', origLine)
        origLine = re.sub(r'\*$', '', origLine)
        origLine = re.sub(r'\*\*', '*', origLine)
        origLine = re.sub(r'\*$', '', origLine)
        #保证domain地址不正则
        if re.search(r'\.', origLine):
          if re.search('\$', origLine):
            origLine = re.sub(r'\.(?=.*\S\$)', '\.', origLine)
          else:
            origLine = re.sub(r'\.','\.', origLine)
        origLine = re.sub(r'\*', '.*', origLine)        
        origLine = re.sub(r'\\\.\\\.', '\.', origLine)
        origLine = re.sub(r'\?', '\?', origLine)
               
        origLine = re.sub(r'domain\=', 'd=', origLine)
        origLine = re.sub(r'\,d\=', ',$d=', origLine)        
        #origLine = re.sub(r'\$d\=', '$d=', origLine)
        origLine = re.sub(r'\^','\/', origLine)
        origLine = re.sub(r'^@@\|\|', ':\/\/([^\/]+\.)?', origLine)      
        origLine = re.sub(r'^@@\|', '^', origLine)
        origLine = re.sub(r'^\|\|', ':\/\/([^\/]+\.)?', origLine)      
        origLine = re.sub(r'^\|', '^', origLine)
        origLine = re.sub('\\\/\\\.\*', '', origLine)
        origLine = re.sub('\\\/\\\/\/', '/', origLine)
        

        
        
        
        #处理各种规则选项
        origLine = re.sub('object_subrequest','object', origLine)
        origLine = re.sub('subdocument','document', origLine)
        if origLine.find('[\$\,]elemhide'):
          pass
        
        #把domain后的/放到域名后
        #if re.search(r'\$.*\=|\d', origLine):
          #origLine = re.sub(r'\/$', '', origLine)
          #if re.search(r'  \$',origLine):
            #origLine = re.sub(r'  \$', '/	$', origLine)
          #else:
            #origLine = re.sub(r'\$', '/	$', origLine)
        #添加白名单后缀标识
        origLine = origLine + '$w'
        #如果domain和whitelist放在一起，就用,隔开
        #如果这一行有三个选项$的话
        
          #接着是第二三个
          #origLine = re.sub(r'(?<=\,)\$
        #增加正则标识
        origLine = '/' + origLine + '/'
        #把结尾管状符换成$
        origLine = re.sub('\|\/', '$/', origLine)
        #把错误放在最后的/放到域名后        
        if re.search(r'\$w\/$', origLine):
          origLine = re.sub(r'\/$','', origLine)
          if re.search(r'\$.*(?=\$)', origLine):
            if re.search(r'(?=\$).*\$w.*(?=\$)*', origLine):
              origLine = re.sub(r'\$w',',$w', origLine)
          
          origLine = re.sub(r'	\$','/	$', origLine)
          origLine = re.sub(r'\/	\$w','	$w', origLine)
        if re.search(r'\$(?=.+\$.+\$)', origLine):
          #把前面是地址的第一个$给替换成 $了
          origLine = re.sub(r'\$(?=.+\$.+\$)','/	$', origLine)
        elif re.search(r'\$(?=.+\$)', origLine):
          origLine = re.sub(r'\$(?=.+\$)','/	$', origLine)
        #把$t加上去
        origLine = re.sub(r'\$(?![(d\=)|(t\=)|(\$w)])','$t=', origLine)
          
          
          
          #把前面是地址$的给替换成 $了
          #origLine = re.sub(r'(?<=\/)\$','  $', origLine)
          #
          #origLine = re.sub(r'\$',',$', origLine)
          #origLine = re.sub(r',d',',$d', origLine)
          #origLine = re.sub(r'\/,\$','/$', origLine)
        
        result.append(origLine)
      else:
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        match = re.search(r'^(\|\||\|w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 修改各种标记
          #猎豹浏览器暂不支持domain~的排除规则，删掉排除
          line = re.sub(r'\|~[^|]+(?=\|)', '', line)
          line = re.sub(r'\|~[^|]+$', '', line)
          line = re.sub(r'\$domain=~[^|]+$', '', line)
          
          line = re.sub(r'^\|\*', '', line)
          line = re.sub(r'\*\|$', '$', line)
          line = re.sub(r'\/', '\/', line)
          line = re.sub(r'\*$', '', line)
          line = re.sub(r'\*\*', '*', line)
          line = re.sub(r'\*$', '', line)
          #保证domain地址不正则
          if re.search(r'\.', line):
            if re.search('\$', line):
              line = re.sub(r'\.(?=.*\S\$)', '\.', line)
            else:
              line = re.sub(r'\.','\.', line)
          line = re.sub(r'\*', '.*', line)          
          line = re.sub(r'\\\.\\\.', '\.', line)
          line = re.sub(r'\?', '\?', line)          
          line = re.sub(r'domain\=', 'd=', line)
          line = re.sub(r'\,d\=', ',$d=', line)
          #line = re.sub(r'\$d\=', '  $d=', line)
          line = re.sub('\\\/\\\.\*', '', line)
          line = re.sub('\\\/\\\/\/', '/', line)
          line = re.sub(r'\^','\/', line)
          line = re.sub(r'^\|\|', ':\/\/([^\/]+\.)?', line)
          line = re.sub(r'^\|', '^', line)
          line = re.sub(r'\$(?![(d\=)|(t\=)|(\$w)])','$t=', line)
          if re.search(r'\$w\/$', line):
            line = re.sub(r'\/$','', line)
            line = re.sub(r'\$w',',$w', line)
            line = re.sub(r'  \$','/  $', line)
            line = re.sub(r'\/	\$w','  $w', line)
          if re.search(r'\$(?=.+\$.+\$)', line):
            #把前面是地址的第一个$给替换成 $了
            line = re.sub(r'\$(?=.+\$.+\$)','/  $', line)
          elif re.search(r'\$(?=.+\$)', origLine):
            line = re.sub(r'\$(?=.+\$)','/  $', line)



        '''match = re.search(r'^(\@\@\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 修改各种标记
          line = re.sub(r'@@.*', r'.*	$w', line)'''
      # 删除规则尾的标记
        line = re.sub(r'\|$', '$', line)
        # 删除不必要的两端的管状符
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          line += ' $t=script'
		#猎豹版不用删除http://
        #if line.startswith('http://'): #要删除的规则中的字符串
          #line = line[7:] #前面一个数字是上一行字符串的字符数
        if domain:
          #猎豹浏览器暂不支持domain~的排除规则，删掉排除
          line = re.sub(r'\|~[^|]+(?=\|)', '', line)
          line = re.sub(r'\|~[^|]+$', '', line)
          line = re.sub(r'\$domain=~[^|]+$', '', line)
          
          line = re.sub(r'\s+/$', '', line) #去掉||行符号
          line = re.sub(r'\/', '\/', line)
          line = re.sub(r'\/\*\/$','\//', line)
          line = re.sub(r'\*\|$', '$', line)
          line = re.sub(r'\*$', '', line)
          line = re.sub(r'\*\*', '*', line)
          line = re.sub(r'\*$', '', line)
          #保证domain地址不正则
          if re.search(r'\.', line):
            if re.search('\$', line):
              line = re.sub(r'\.(?=.*\S\$)', '\.', line)
            else:
              line = re.sub(r'\.','\.', line)
              
          line = re.sub(r'\*', '.*', line)          
          line = re.sub(r'\\\.\\\.', '\.', line)
          line = re.sub(r'\?', '\?', line)          
          line = re.sub(r'domain\=', 'd=', line)
          line = re.sub(r'\,d\=', ',$d=', line)
          line = re.sub(r'\^','\/', line)
          #line = re.sub(r'\$d\=', '  $d=', line)
          line = '/:\/\/([^\/]+\.)?%s%s/%s' % ( domain, line, '	$w' if  isException  else '')         
          if re.search(r'\$w\/$', line):
            line = re.sub(r'\/$','', line)
            line = re.sub(r'\$w',',$w', line)
            line = re.sub(r'  \$','/  $', line)
            line = re.sub(r'\/	\$w','  $w', line)
          if re.search(r'\$(?=.+\$.+\$)', line):
            #把前面是地址的第一个$给替换成 $了
            line = re.sub(r'\$(?=.+\$.+\$)','/  $', line)
          elif re.search(r'\$(?=.+\$)', origLine):
            line = re.sub(r'\$(?=.+\$)','/  $', line)


          line = re.sub(r'\$(?![(d\=)|(t\=)|(\$w)])','$t=', line)
          
          result.append(line)
        elif isException:
          # 没有域的例外规则
          #猎豹浏览器暂不支持domain~的排除规则，删掉排除
          origLine = re.sub(r'\|~[^|]+(?=\|)', '', origLine)
          origLine = re.sub(r'\|~[^|]+$', '', origLine)
          origLine = re.sub(r'\$domain=~[^|]+$', '', origLine)
          
          origLine = re.sub(r'\^','\/', origLine)
          origLine = re.sub(r'^@@\|\*', '', origLine)
          origLine = re.sub(r'^@@\|\|', ':\/\/([^\/]+\.)?', origLine)
          origLine = re.sub(r'^@@\|', '^', origLine)
          origLine = re.sub(r'^@@', '', origLine)
          origLine = re.sub(r'\*\|$', '$', origLine)
          origLine = re.sub(r'\*$', '', origLine)
          origLine = re.sub(r'\*\*', '*', origLine)
          origLine = re.sub(r'\*$', '', origLine)
          #保证domain地址不正则
          if re.search(r'\.', origLine):
            if re.search('\$', origLine):
              origLine = re.sub(r'\.(?=.*\S\$)', '\.', origLine)
            else:
              origLine = re.sub(r'\.','\.', origLine)
          origLine = re.sub(r'\*', '.*', origLine)          
          origLine = re.sub(r'\\\.\\\.', '\.', origLine)
          origLine = re.sub(r'\?', '\?', origLine)
          origLine = re.sub(r'\/', '\/', origLine)
          origLine = re.sub(r'domain\=', 'd=', origLine)
          origLine = re.sub(r'\,d\=', ',$d=', origLine)
          #origLine = re.sub(r'', '$d=', origLine)
          #origLine = re.sub(r'\$d\=', '  $d=', origLine)
          #正则标识
          origLine = '/' + origLine + '/' '	$w'
          #把结尾管状符换成$
          origLine = re.sub('\|\/', '$/', origLine)
          #把错误放在最后的/放到域名后        
          if re.search(r'\$w\/$', origLine):
            #origLine = re.sub(r'\/$','', origLine)
            if re.search(r'\$.*(?=\$)', origLine):
              if re.search(r'(?=\$).*\$w.*(?=\$)*', origLine):
                origLine = re.sub(r'\$w',',$w', origLine)
              
            origLine = re.sub(r'  \$','/  $', origLine)
          origLine = re.sub(r'\$(?![(d\=)|(t\=)|(\$w)])','$t=', origLine)
          if re.search(r'\$w\/$', origLine):
            origLine = re.sub(r'\/$','', origLine)
            origLine = re.sub(r'\$w',',$w', origLine)
            origLine = re.sub(r'  \$','/  $', origLine)
            origLine = re.sub(r'\/	\$w','  $w', origLine)
          if re.search(r'\$(?=.+\$.+\$)', origLine):
            #把前面是地址的第一个$给替换成 $了
           origLine = re.sub(r'\$(?=.+\$.+\$)','/  $', origLine)
          elif re.search(r'\$(?=.+\$)', origLine):
            origLine = re.sub(r'\$(?=.+\$)','/  $', origLine)
          #猎豹暂时不支持domain=~的规则，去掉。  
          if re.search(r'((	|,)\$d=~[^,]+$)|((?<=(	|,)\$d=)~[^,]*,)|((?<=,)~[^,]*,)|((?<=,)~[^,]*$)',origLine):
            origLine = re.sub(r'((	|,)\$d=~[^,]+$)|((?<=(	|,)\$d=)~[^,]*,)|((?<=,)~[^,]*,)|((?<=,)~[^,]*$)', '', origLine)
          result.append(origLine)
    
        else:
          #处理到这里基本就是空白行的处置了
          line = re.sub(r'^\/\/$','', '/' + line + '/')


          
          '''if re.search(r'^\/\w', line):
            
            line = re.sub(r'^\/',':\/\/([^\/]+\.)?', line)'''
          result.append(line)
          

  conditionalWrite(filePath, '\n'.join(result) + '\n')

def usage():
  print '''Usage: %s [source_dir] [output_dir]

Options:
  -h          --help              Print this message and exit
  -t seconds  --timeout=seconds   Timeout when fetching remote subscriptions
''' % os.path.basename(sys.argv[0])

if __name__ == '__main__':
  try:
    opts, args = getopt(sys.argv[1:], 'ht:', ['help', 'timeout='])
  except GetoptError, e:
    print str(e)
    usage()
    sys.exit(2)

  sourceDir, targetDir =  '.', 'Temp'
  if len(args) >= 1:
    sourceDir = args[0]
  if len(args) >= 2:
    targetDir = args[1]

  timeout = 30
  for option, value in opts:
    if option in ('-h', '--help'):
      usage()
      sys.exit()
    elif option in ('-t', '--timeout'):
      timeout = int(value)

  if os.path.exists(os.path.join(sourceDir, '.hg')):
    # Our source is a Mercurial repository, try updating
    subprocess.Popen(['hg', '-R', sourceDir, 'pull', '--update']).communicate()

  combineSubscriptions(sourceDir, targetDir, timeout)

  #笔记：(#|!)\-+[^\-]*\n    匹配无效分类
  #     (#|!)\-+【广告强效过滤规则.* 匹配第一行规则标题
#把临时生成的文件移动回根目录
'''import shutil
import os
if os.path.isfile('.' + 'rules_for_liebao.txt'):
  os.system('rm -fr rules_for_liebao.txt')
else:
  shutil.copy('./Temp/rules_for_liebao.txt', '.')'''
#把临时生成的文件移动回根目录，同时去除所有的空白行
# coding=utf-8
file1 = open("./Temp/rules_for_liebao.txt","r")
file2 = open("rules_for_liebao.txt","w")
while 1:
 text = file1.readline()
 if( text == '' ):
  break
 elif( text != '\n'):
  file2.write( text )
file1.close()
file2.close()

#===金山版===
#!/usr/bin/env python
# coding: utf-8

# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/

import sys, os, re, subprocess, urllib2, time, traceback, codecs, hashlib, base64
from getopt import getopt, GetoptError

acceptedExtensions = {
  '.txt': True,
}
ignore = {
  'rules_for_KSafe.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Plus_Rules.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
  'rules_for_360.txt': True,
  'rules_for_ESET[1].txt': True,
  'rules_for_ESET[2].txt': True,
  'rules_for_Kaspersky.txt': True,
  
}
verbatim = {
  'COPYING': True,
}

def combineSubscriptions(sourceDir, targetDir, timeout=30):
  global acceptedExtensions, ignore, verbatim

  if not os.path.exists(targetDir):
    os.makedirs(targetDir, 0755)

  known = {}
  for file in os.listdir(sourceDir):
    if file in ignore or file[0] == '.' or not os.path.isfile(os.path.join(sourceDir, file)):
      continue
    if file in verbatim:
      processVerbatimFile(sourceDir, targetDir, file)
    elif not os.path.splitext(file)[1] in acceptedExtensions:
      continue
    else:
      try:
        processSubscriptionFile(sourceDir, targetDir, file, timeout)
      except:
        print >>sys.stderr, '错误处理订阅文件 "%s"' % file
        traceback.print_exc()
        print >>sys.stderr
      known['rules_for_KSafe.txt'] = True
    known[file] = True


  for file in os.listdir(targetDir):
    if file[0] == '.':
      continue
    if not file in known:
      os.remove(os.path.join(targetDir, file))

def conditionalWrite(filePath, data):
  changed = True
  if os.path.exists(filePath):
    handle = codecs.open(filePath, 'rb', encoding='utf-8')
    oldData = handle.read()
    handle.close()

    checksumRegExp = re.compile(r'^.*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n', re.M | re.I)
    oldData = re.sub(checksumRegExp, '', oldData)
    oldData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', oldData)
    newData = re.sub(checksumRegExp, '', data)
    newData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', newData)
    if oldData == newData:
      changed = False
  if changed:
    handle = codecs.open(filePath, 'wb', encoding='utf-8')
    handle.write(data)
    handle.close()
    

def processVerbatimFile(sourceDir, targetDir, file):
  handle = codecs.open(os.path.join(sourceDir, file), 'rb', encoding='utf-8')
  conditionalWrite(os.path.join(targetDir, file), handle.read())
  handle.close()

def processSubscriptionFile(sourceDir, targetDir, file, timeout):
  filePath = os.path.join(sourceDir, file)
  handle = codecs.open(filePath, 'rb', encoding='utf-8')
  lines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
  handle.close()

  header = ''
  if len(lines) > 0:
    header = lines[0]
    del lines[0]
  if not re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', header, re.I):
    raise Exception('这是不是一个有效的Adblock Plus的订阅文件。')

  lines = resolveIncludes(filePath, lines, timeout)
  lines = filter(lambda l: l != '' and not re.search(r'!\s*checksum[\s\-:]+([\w\+\/=]+)', l, re.I), lines)

  writeRule(os.path.join(targetDir, 'rules_for_KSafe.txt'), lines)

  checksum = hashlib.md5()
  checksum.update((header + '\n' + '\n'.join(lines) + '\n').encode('utf-8'))
  lines.insert(0, '! Checksum: %s' % re.sub(r'=', '', base64.b64encode(checksum.digest())))
  lines.insert(0, header)
  conditionalWrite(os.path.join(targetDir, file), '\n'.join(lines) + '\n')

def resolveIncludes(filePath, lines, timeout, level=0):
  if level > 5:
    raise Exception('有太多的嵌套包含，这可能是循环引用的地方。')

  result = []
  for line in lines:
    match = re.search(r'^\s*%include\s+(.*)%\s*$', line)
    if match:
      file = match.group(1)
      newLines = None
      if re.match(r'^https?://', file):
        result.append('! *** Fetched from: %s ***' % file)

        request = urllib2.urlopen(file, None, timeout)
        charset = 'utf-8'
        contentType = request.headers.get('content-type', '')
        if contentType.find('charset=') >= 0:
          charset = contentType.split('charset=', 1)[1]
        newLines = unicode(request.read(), charset).split('\n')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), newLines)
        newLines = filter(lambda l: not re.search(r'^\s*!.*?\bExpires\s*(?::|after)\s*(\d+)\s*(h)?', l, re.M | re.I), newLines)
      else:
        result.append('! *** %s ***' % file)

        parentDir = os.path.dirname(filePath)
        includePath = os.path.join(parentDir, file)
        relPath = os.path.relpath(includePath, parentDir)
        if len(relPath) == 0 or relPath[0] == '.':
          raise Exception('无效包括 "%s", 需要是一个 HTTP/HTTPS 地址或一个相对文件路径' % file)

        handle = codecs.open(includePath, 'rb', encoding='utf-8')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
        newLines = resolveIncludes(includePath, newLines, timeout, level + 1)
        handle.close()

      if len(newLines) and re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        del newLines[0]
      result.extend(newLines)
    else:
      if line.find('%timestamp%') >= 0:
        if level == 0:
          line = line.replace('%timestamp%', time.strftime('%d %b %Y %H:%M UTC', time.gmtime()))
        else:
          line = ''
      result.append(line)
  return result

def writeRule(filePath, lines):
  result = []
  for line in lines:
    if re.search(r'^!', line):
      #把各种注释内容替换掉
      #line = re.sub(r'(#|!)\-+[^\-]*$','', line)
      line = re.sub(r'^!.*$','', line)
      #由于猎豹有些问题，暂时使用短名称
      #line = re.sub('for ABP', 'for liebao', line)
      result.append(line)
    elif line.find('#') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    elif line.find('@@') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    else:
      # We have a blocking or exception rule, try to convert it
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = line[2:]

        

      hasUnsupportedOptions = False
      requiresScript = False
      match = re.search(r'^(.*?)\$(.*)', line)
      if match:
        # This rule has options, check whether any of them are important
        line = match.group(1)
        options = match.group(2).replace('_', '-').lower().split(',')

        # A number of options are not supported in MSIE but can be safely ignored, remove them
        options = filter(lambda o: not o in ('', 'third-party', '~third-party', 'match-case', '~match-case', '~object-subrequest', '~other', '~donottrack'), options)

        # Also ignore domain negation of whitelists
        if isException:
          options = filter(lambda o: not o.startswith('domain=~'), options)

        if 'donottrack' in options:
          # Rules with donottrack option should always be removed
          hasUnsupportedOptions = True
          
        unsupportedOptions = 0
        
        if 'object-subrequest' in options:
          # The rule applies to object subrequests, which may not be filtered by TPLs
          unsupportedOptions += 1
        if 'elemhide' in options:
          # The rule prevents the hiding of elements, which is not possible with TPLs
          unsupportedOptions += 1
          
        if unsupportedOptions >= len(options):
          # The rule only applies to unsupported options
          hasUnsupportedOptions = True
        else:
          # The rule has other significant options that need to be evaluated
          if 'script' in options and (len(options) - unsupportedOptions) == 1:
            # Mark rules that only apply to scripts for approximate conversion
            requiresScript = True
          else:
            # The rule has further options that aren't available in TPLs.
            # Unless an exception rule is specific to a domain, all remaining
            # options are ignored to avoid potential false positives.
            if isException:
              hasUnsupportedOptions = any([o.startswith('domain=') for o in options])
            else:
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:
        # 不包括不支持的选项的过滤器
        origLine = re.sub(r'^\|\|', '', origLine)
        origLine = re.sub(r'^\|', '', origLine)
        origLine = re.sub(r'\$d.*$','', origLine)
        #去掉http://
        if origLine.startswith('http://'):
          origLine = origLine[7:] #前面一个数字是上一行字符串的字符数
        result.append('5,4,' + origLine)
      else:
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        match = re.search(r'^(\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 没有域名信息，删除规则头的标记
          line = re.sub(r'^\|\|', '', line)
          line = re.sub(r'^\|', '', line)
        # 删除规则尾的标记
        line = re.sub(r'\|$', '', line)
        # 删除不必要的两端的管状符
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          line += '*.js*'
        if line.startswith('http://'):
          line = line[7:] #前面一个数字是上一行字符串的字符数
        if domain:
          line = '5,4,%s%s%s' % ('+' if isException else '', domain, line)
          line = re.sub(r'\s+/$', '', line)
          result.append(line)
        elif isException:
          # 没有域的例外规则不受支持
          result.append('!' + origLine)
        else:
          result.append('5,4,' + line)
  conditionalWrite(filePath, '\r\n'.join(result) + '\r\n')

def usage():
  print '''Usage: %s [source_dir] [output_dir]

Options:
  -h          --help              Print this message and exit
  -t seconds  --timeout=seconds   Timeout when fetching remote subscriptions
''' % os.path.basename(sys.argv[0])

if __name__ == '__main__':
  try:
    opts, args = getopt(sys.argv[1:], 'ht:', ['help', 'timeout='])
  except GetoptError, e:
    print str(e)
    usage()
    sys.exit(2)

  sourceDir, targetDir =  '.', 'Temp'
  if len(args) >= 1:
    sourceDir = args[0]
  if len(args) >= 2:
    targetDir = args[1]


  timeout = 30
  for option, value in opts:
    if option in ('-h', '--help'):
      usage()
      sys.exit()
    elif option in ('-t', '--timeout'):
      timeout = int(value)

  if os.path.exists(os.path.join(sourceDir, '.hg')):
    # Our source is a Mercurial repository, try updating
    subprocess.Popen(['hg', '-R', sourceDir, 'pull', '--update']).communicate()


    
  combineSubscriptions(sourceDir, targetDir, timeout)

  #笔记：(#|!)\-+[^\-]*\n    匹配无效分类
  #     (#|!)\-+【广告强效过滤规则.* 匹配第一行规则标题
#把临时生成的文件移动回根目录
'''import shutil
import os
if os.path.isfile('.' + 'rules_for_KSafe.txt'):
  os.system('rm -fr rules_for_KSafe.txt')
else:
  shutil.copy('./Temp/rules_for_KSafe.txt', '.')'''
#把临时生成的文件移动回根目录，同时去除所有的空白行
# coding=utf-8
file1 = open("./Temp/rules_for_KSafe.txt","r")
file2 = open("rules_for_KSafe.txt","w")
while 1:
 text = file1.readline()
 if( text == '' ):
  
  break
 elif( text != '\n'):
  file2.write( text )
file1.close()
file2.close()

#===Avast版===
#!/usr/bin/env python
# coding: utf-8

# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/

import sys, os, re, subprocess, urllib2, time, traceback, codecs, hashlib, base64
from getopt import getopt, GetoptError


acceptedExtensions = {
  '.txt': True,
}
ignore = {
  'rules_for_KSafe.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Plus_Rules.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
  'rules_for_360.txt': True,
  'rules_for_ESET[1].txt': True,
  'rules_for_ESET[2].txt': True,
  'rules_for_Kaspersky.txt': True,
  
}
verbatim = {
  'COPYING': True,
}

def combineSubscriptions(sourceDir, targetDir, timeout=30):
  global acceptedExtensions, ignore, verbatim

  if not os.path.exists(targetDir):
    os.makedirs(targetDir, 0755)

  known = {}
  for file in os.listdir(sourceDir):
    if file in ignore or file[0] == '.' or not os.path.isfile(os.path.join(sourceDir, file)):
      continue
    if file in verbatim:
      processVerbatimFile(sourceDir, targetDir, file)
    elif not os.path.splitext(file)[1] in acceptedExtensions:
      continue
    else:
      try:
        processSubscriptionFile(sourceDir, targetDir, file, timeout)
      except:
        print >>sys.stderr, '错误处理订阅文件 "%s"' % file
        traceback.print_exc()
        print >>sys.stderr
      known['WebShield.ini'] = True
    known[file] = True

  for file in os.listdir(targetDir):
    if file[0] == '.':
      continue
    if not file in known:
      os.remove(os.path.join(targetDir, file))


def conditionalWrite(filePath, data):
  changed = True
  if os.path.exists(filePath):
    handle = codecs.open(filePath, 'rb', encoding='utf-8')
    oldData = handle.read()
    handle.close()

    checksumRegExp = re.compile(r'^.*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n', re.M | re.I)
    oldData = re.sub(checksumRegExp, '', oldData)
    oldData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', oldData)
    newData = re.sub(checksumRegExp, '', data)
    newData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', newData)
    if oldData == newData:
      changed = False
  if changed:
    handle = codecs.open(filePath, 'wb', encoding='utf-8')
    handle.write(data)
    handle.close()
    

def processVerbatimFile(sourceDir, targetDir, file):
  handle = codecs.open(os.path.join(sourceDir, file), 'rb', encoding='utf-8')
  conditionalWrite(os.path.join(targetDir, file), handle.read())
  handle.close()

def processSubscriptionFile(sourceDir, targetDir, file, timeout):
  filePath = os.path.join(sourceDir, file)
  handle = codecs.open(filePath, 'rb', encoding='utf-8')
  lines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
  handle.close()

  header = ''
  if len(lines) > 0:
    header = lines[0]
    del lines[0]
  if not re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', header, re.I):
    raise Exception('这是不是一个有效的Adblock Plus的订阅文件。')

  lines = resolveIncludes(filePath, lines, timeout)
  lines = filter(lambda l: l != '' and not re.search(r'!\s*checksum[\s\-:]+([\w\+\/=]+)', l, re.I), lines)

  writeRule(os.path.join(targetDir, 'WebShield.ini'), lines)

  checksum = hashlib.md5()
  checksum.update((header + '\n' + '\n'.join(lines) + '\n').encode('utf-8'))
  lines.insert(0, '! Checksum: %s' % re.sub(r'=', '', base64.b64encode(checksum.digest())))
  lines.insert(0, header)
  conditionalWrite(os.path.join(targetDir, file), '\n'.join(lines) + '\n')

def resolveIncludes(filePath, lines, timeout, level=0):
  if level > 5:
    raise Exception('有太多的嵌套包含，这可能是循环引用的地方。')


  result = []
  for line in lines:
    match = re.search(r'^\s*%include\s+(.*)%\s*$', line)
    if match:
      file = match.group(1)
      newLines = None
      if re.match(r'^https?://', file):
        result.append('! *** Fetched from: %s ***' % file)


        charset = 'utf-8'
        contentType = request.headers.get('content-type', '')
        if contentType.find('charset=') >= 0:
          charset = contentType.split('charset=', 1)[1]
        newLines = unicode(request.read(), charset).split('\n')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), newLines)
      else:
        result.append('! *** %s ***' % file)

        parentDir = os.path.dirname(filePath)
        includePath = os.path.join(parentDir, file)
        relPath = os.path.relpath(includePath, parentDir)
        if len(relPath) == 0 or relPath[0] == '.':
          raise Exception('无效包括 "%s", 需要是一个 HTTP/HTTPS 地址或一个相对文件路径' % file)

        handle = codecs.open(includePath, 'rb', encoding='utf-8')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
        newLines = resolveIncludes(includePath, newLines, timeout, level + 1)
        handle.close()
        


	  
        
      if len(newLines) and re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        del newLines[0]
      result.extend(newLines)
  
    else:
      if line.find('%timestamp%') >= 0:
        if level == 0:
          line = line.replace('%timestamp%', time.strftime('%d %b %Y %H:%M UTC', time.gmtime()))
        else:
          line = ''
      result.append(line)
  return result

def writeRule(filePath, lines):
  result = []
  for line in lines:
    if re.search(r'^!', line):
      # 这是注释，去除。
      if line.find(r'!\-+.*$') >= 0:
        pass
      '''result.append(re.sub(r'!\-+.*$', '',  line))
    if re.search(r'\n\s*\n', lines):
      result.append(re.sub(r'\n\s*\n', '',  lines))'''
    elif line.find('#') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    elif line.find('@@') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    else:
      # We have a blocking or exception rule, try to convert it
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = line[2:]

        

      hasUnsupportedOptions = False
      requiresScript = False
      match = re.search(r'^(.*?)\$(.*)', line)
      if match:
        # This rule has options, check whether any of them are important
        line = match.group(1)
        options = match.group(2).replace('_', '-').lower().split(',')

        # A number of options are not supported in MSIE but can be safely ignored, remove them
        options = filter(lambda o: not o in ('', 'third-party', '~third-party', 'match-case', '~match-case', '~object-subrequest', '~other', '~donottrack'), options)

        # Also ignore domain negation of whitelists
        if isException:
          options = filter(lambda o: not o.startswith('domain=~'), options)

        if 'donottrack' in options:
          # Rules with donottrack option should always be removed
          hasUnsupportedOptions = True
          
        unsupportedOptions = 0
        
        if 'object-subrequest' in options:
          # The rule applies to object subrequests, which may not be filtered by TPLs
          unsupportedOptions += 1
        if 'elemhide' in options:
          # The rule prevents the hiding of elements, which is not possible with TPLs
          unsupportedOptions += 1
          
        if unsupportedOptions >= len(options):
          # The rule only applies to unsupported options
          hasUnsupportedOptions = True
        else:
          # The rule has other significant options that need to be evaluated
          if 'script' in options and (len(options) - unsupportedOptions) == 1:
            # Mark rules that only apply to scripts for approximate conversion
            requiresScript = True
          else:
            # The rule has further options that aren't available in TPLs.
            # Unless an exception rule is specific to a domain, all remaining
            # options are ignored to avoid potential false positives.
            if isException:
              hasUnsupportedOptions = any([o.startswith('domain=') for o in options])
            else:
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:
        # 不包括不支持的选项的过滤器
        origLine = re.sub(r'^\|\|', '', origLine)
        origLine = re.sub(r'^\|', '', origLine)
        origLine = re.sub(r'\$.*$','', origLine)
        #去掉http://
        if origLine.startswith('http://'):
          origLine = origLine[7:] #前面一个数字是上一行字符串的字符数
        result.append('5,4,' + origLine)
      else:
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        match = re.search(r'^(\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 没有域名信息，删除规则头的标记
          line = re.sub(r'^\|\|', '', line)
          line = re.sub(r'^\|', '', line)
        # 删除规则尾的标记
        line = re.sub(r'\|$', '', line)
        # 删除不必要的两端的管状符
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          line += '*.js'
        if line.startswith('http://'):
          line = line[7:] #前面一个数字是上一行字符串的字符数
        if domain:
          line = '%s%s%s' % ('+' if isException else '', domain, line)
          line = re.sub(r'\s+/$', '', line)
          result.append(line)
        elif isException:
          # 没有域的例外规则不受支持
          result.append('!' + origLine)
        else:
          result.append('' + line)
  #规则头
  head = '''[WebScanner]
HttpRedirectPort=80,8080,8091,8081,8008,8888,3124,3127,3128
HttpRedirectPortUpdated1=1
URLBlocking=1
IgnoreAddress=
IgnoreLocalhost=1
ExcludedTypes=1
ExcludedTypesList=image/gif;image/png;audio/*;video/*
ExcludedURLs=0
HttpScanParamFlag=1
IntelligentStreamScanning=1
WebScanning=1
BlockedURLs='''
  #规则尾
  bottom = '''[Common]
ProviderEnabled=1
OverwriteReport=0
PUPAction=abort
Report=TXT
ReportName=*
ReportRecords=Infected;HardErrors;SoftErrors
ScanFullFiles=0
ScanPUP=0
ScanPackers=All
ShowAppliedActionNotification=1
SuspiciousAction=abort
TaskSensitivity=100
UseCodeEmulation=1
VirusAction=abort'''
  #输出到文件  
  conditionalWrite(filePath, head +  ';'.join(result) + '\r\n' + bottom)

def usage():
  print '''Usage: %s [source_dir] [output_dir]

Options:
  -h          --help              Print this message and exit
  -t seconds  --timeout=seconds   Timeout when fetching remote subscriptions
''' % os.path.basename(sys.argv[0])

if __name__ == '__main__':
  try:
    opts, args = getopt(sys.argv[1:], 'ht:', ['help', 'timeout='])
  except GetoptError, e:
    print str(e)
    usage()
    sys.exit(2)

  sourceDir, targetDir =  '.', 'Temp'
  if len(args) >= 1:
    sourceDir = args[0]
  if len(args) >= 2:
    targetDir = args[1]


  timeout = 30
  for option, value in opts:
    if option in ('-h', '--help'):
      usage()
      sys.exit()
    elif option in ('-t', '--timeout'):
      timeout = int(value)

  if os.path.exists(os.path.join(sourceDir, '.hg')):
    # Our source is a Mercurial repository, try updating
    subprocess.Popen(['hg', '-R', sourceDir, 'pull', '--update']).communicate()


    
  combineSubscriptions(sourceDir, targetDir, timeout)

  #笔记：(#|!)\-+[^\-]*\n    匹配无效分类
  #     (#|!)\-+【广告强效过滤规则.* 匹配第一行规则标题
#把换行符替换为;并把临时生成的文件移动回根目录

'''#读取文件
file1 = open("./Temp/WebShield.ini","r")
#file2 = open("WebShield.ini","w")
#把换行符替换为;
#sp = re.compile('\n+') 
rules = file1.readlines() #读取全部内容
rules = ';'.join(rules)
rules = rules ,

file1 = open("./Temp/WebShield.ini","w")

file1.write(rules)
file1.close()
#file2.close()'''

#把临时生成的文件移动回根目录
import shutil
import os
if os.path.isfile('.' + 'WebShield.ini'):
  os.system('rm -fr WebShield.ini')
else:
  shutil.copy('./Temp/WebShield.ini', '.')

#===Opera===
#!/usr/bin/env python
# coding: utf-8

# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/

import sys, os, re, subprocess, urllib2, time, traceback, codecs, hashlib, base64
from getopt import getopt, GetoptError


acceptedExtensions = {
  '.txt': True,
}
ignore = {
  'rules_for_KSafe.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Plus_Rules.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
  'rules_for_360.txt': True,
  'rules_for_ESET[1].txt': True,
  'rules_for_ESET[2].txt': True,
  'rules_for_Kaspersky.txt': True,
  
}
verbatim = {
  'COPYING': True,
}

def combineSubscriptions(sourceDir, targetDir, timeout=30):
  global acceptedExtensions, ignore, verbatim

  if not os.path.exists(targetDir):
    os.makedirs(targetDir, 0755)

  known = {}
  for file in os.listdir(sourceDir):
    if file in ignore or file[0] == '.' or not os.path.isfile(os.path.join(sourceDir, file)):
      continue
    if file in verbatim:
      processVerbatimFile(sourceDir, targetDir, file)
    elif not os.path.splitext(file)[1] in acceptedExtensions:
      continue
    else:
      try:
        processSubscriptionFile(sourceDir, targetDir, file, timeout)
      except:
        print >>sys.stderr, '错误处理订阅文件 "%s"' % file
        traceback.print_exc()
        print >>sys.stderr
      known['urlfilter.ini'] = True
    known[file] = True

  for file in os.listdir(targetDir):
    if file[0] == '.':
      continue
    if not file in known:
      os.remove(os.path.join(targetDir, file))


def conditionalWrite(filePath, data):
  changed = True
  if os.path.exists(filePath):
    handle = codecs.open(filePath, 'rb', encoding='utf-8')
    oldData = handle.read()
    handle.close()

    checksumRegExp = re.compile(r'^.*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n', re.M | re.I)
    oldData = re.sub(checksumRegExp, '', oldData)
    oldData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', oldData)
    newData = re.sub(checksumRegExp, '', data)
    newData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', newData)
    if oldData == newData:
      changed = False
  if changed:
    handle = codecs.open(filePath, 'wb', encoding='utf-8')
    handle.write(data)
    handle.close()
    

def processVerbatimFile(sourceDir, targetDir, file):
  handle = codecs.open(os.path.join(sourceDir, file), 'rb', encoding='utf-8')
  conditionalWrite(os.path.join(targetDir, file), handle.read())
  handle.close()

def processSubscriptionFile(sourceDir, targetDir, file, timeout):
  filePath = os.path.join(sourceDir, file)
  handle = codecs.open(filePath, 'rb', encoding='utf-8')
  lines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
  handle.close()

  header = ''
  if len(lines) > 0:
    header = lines[0]
    del lines[0]
  if not re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', header, re.I):
    raise Exception('这是不是一个有效的Adblock Plus的订阅文件。')

  lines = resolveIncludes(filePath, lines, timeout)
  lines = filter(lambda l: l != '' and not re.search(r'!\s*checksum[\s\-:]+([\w\+\/=]+)', l, re.I), lines)

  writeRule(os.path.join(targetDir, 'urlfilter.ini'), lines)

  checksum = hashlib.md5()
  checksum.update((header + '\n' + '\n'.join(lines) + '\n').encode('utf-8'))
  lines.insert(0, '! Checksum: %s' % re.sub(r'=', '', base64.b64encode(checksum.digest())))
  lines.insert(0, header)
  conditionalWrite(os.path.join(targetDir, file), '\n'.join(lines) + '\n')

def resolveIncludes(filePath, lines, timeout, level=0):
  if level > 5:
    raise Exception('有太多的嵌套包含，这可能是循环引用的地方。')


  result = []
  for line in lines:
    match = re.search(r'^\s*%include\s+(.*)%\s*$', line)
    if match:
      file = match.group(1)
      newLines = None
      if re.match(r'^https?://', file):
        result.append('! *** Fetched from: %s ***' % file)


        charset = 'utf-8'
        contentType = request.headers.get('content-type', '')
        if contentType.find('charset=') >= 0:
          charset = contentType.split('charset=', 1)[1]
        newLines = unicode(request.read(), charset).split('\n')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), newLines)
      else:
        result.append('! *** %s ***' % file)

        parentDir = os.path.dirname(filePath)
        includePath = os.path.join(parentDir, file)
        relPath = os.path.relpath(includePath, parentDir)
        if len(relPath) == 0 or relPath[0] == '.':
          raise Exception('无效包括 "%s", 需要是一个 HTTP/HTTPS 地址或一个相对文件路径' % file)

        handle = codecs.open(includePath, 'rb', encoding='utf-8')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
        newLines = resolveIncludes(includePath, newLines, timeout, level + 1)
        handle.close()
        


	  
        
      if len(newLines) and re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        del newLines[0]
      result.extend(newLines)
  
    else:
      if line.find('%timestamp%') >= 0:
        if level == 0:
          line = line.replace('%timestamp%', time.strftime('%d %b %Y %H:%M UTC', time.gmtime()))
        else:
          line = ''
      result.append(line)
  return result

def writeRule(filePath, lines):
  result = []
  top = u'''Opera Preferences version 2.1\r\n
; Do not edit this file while Opera is running\r\n
; This file is stored in UTF-8 encoding\r\n
; Copyright 2011 xcffl, Apache License 2.0\r\n
\r\n
[prefs]\r\n
prioritize excludelist=1\r\n
\r\n
[include]\r\n
*\r\n
\r\n
[exclude]\r\n'''
  result.append(top)
  for line in lines:
    if re.search(r'^!', line):
      # 这是注释，去除。
      if line.find(r'!\-+.*$') >= 0:
        pass
      '''result.append(re.sub(r'!\-+.*$', '',  line))
    if re.search(r'\n\s*\n', lines):
      result.append(re.sub(r'\n\s*\n', '',  lines))'''
    elif line.find('#') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    elif line.find('@@') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    else:
      # We have a blocking or exception rule, try to convert it
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = line[2:]

        

      hasUnsupportedOptions = False
      requiresScript = False
      match = re.search(r'^(.*?)\$(.*)', line)
      if match:
        # This rule has options, check whether any of them are important
        line = match.group(1)
        options = match.group(2).replace('_', '-').lower().split(',')

        # A number of options are not supported in MSIE but can be safely ignored, remove them
        options = filter(lambda o: not o in ('', 'third-party', '~third-party', 'match-case', '~match-case', '~object-subrequest', '~other', '~donottrack'), options)

        # Also ignore domain negation of whitelists
        if isException:
          options = filter(lambda o: not o.startswith('domain=~'), options)

        if 'donottrack' in options:
          # Rules with donottrack option should always be removed
          hasUnsupportedOptions = True
          
        unsupportedOptions = 0
        
        if 'object-subrequest' in options:
          # The rule applies to object subrequests, which may not be filtered by TPLs
          unsupportedOptions += 1
        if 'elemhide' in options:
          # The rule prevents the hiding of elements, which is not possible with TPLs
          unsupportedOptions += 1
          
        if unsupportedOptions >= len(options):
          # The rule only applies to unsupported options
          hasUnsupportedOptions = True
        else:
          # The rule has other significant options that need to be evaluated
          if 'script' in options and (len(options) - unsupportedOptions) == 1:
            # Mark rules that only apply to scripts for approximate conversion
            requiresScript = True
          else:
            # The rule has further options that aren't available in TPLs.
            # Unless an exception rule is specific to a domain, all remaining
            # options are ignored to avoid potential false positives.
            if isException:
              hasUnsupportedOptions = any([o.startswith('domain=') for o in options])
            else:
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:
        # 不包括不支持的选项的过滤器
        origLine = re.sub(r'^\|\|', '', origLine)
        origLine = re.sub(r'^\|', '', origLine)
        origLine = re.sub(r'\$.*$','', origLine)
        #去掉http://
        if origLine.startswith('http://'):
          origLine = origLine[7:] #前面一个数字是上一行字符串的字符数
        result.append('' + origLine)
      else:
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        match = re.search(r'^(\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 没有域名信息，删除规则头的标记
          line = re.sub(r'^\|\|', '', line)
          line = re.sub(r'^\|', '', line)
        # 删除规则尾的标记
        line = re.sub(r'\|$', '', line)
        # 删除不必要的两端的管状符
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          line += '*.js'
        if line.startswith('http://'):
          line = line[7:] #前面一个数字是上一行字符串的字符数
        if domain:
          line = '%s%s%s' % ('+' if isException else '', domain, line)
          line = re.sub(r'\s+/$', '', line)
          result.append(line)
        elif isException:
          # 没有域的例外规则不受支持
          result.append('!' + origLine)
        else:
          result.append('' + line)
  conditionalWrite(filePath, '\r\n'.join(result) + '\r\n')

def usage():
  print '''Usage: %s [source_dir] [output_dir]

Options:
  -h          --help              Print this message and exit
  -t seconds  --timeout=seconds   Timeout when fetching remote subscriptions
''' % os.path.basename(sys.argv[0])

if __name__ == '__main__':
  try:
    opts, args = getopt(sys.argv[1:], 'ht:', ['help', 'timeout='])
  except GetoptError, e:
    print str(e)
    usage()
    sys.exit(2)

  sourceDir, targetDir =  '.', 'Temp'
  if len(args) >= 1:
    sourceDir = args[0]
  if len(args) >= 2:
    targetDir = args[1]


  timeout = 30
  for option, value in opts:
    if option in ('-h', '--help'):
      usage()
      sys.exit()
    elif option in ('-t', '--timeout'):
      timeout = int(value)

  if os.path.exists(os.path.join(sourceDir, '.hg')):
    # Our source is a Mercurial repository, try updating
    subprocess.Popen(['hg', '-R', sourceDir, 'pull', '--update']).communicate()


    
  combineSubscriptions(sourceDir, targetDir, timeout)

  #笔记：(#|!)\-+[^\-]*\n    匹配无效分类
  #     (#|!)\-+【广告强效过滤规则.* 匹配第一行规则标题
#把临时生成的文件移动回根目录
import shutil
import os
if os.path.isfile('.' + 'urlfilter.ini'):
  os.system('rm -fr urlfilter.ini')
else:
  shutil.copy('./Temp/urlfilter.ini', '.')
  
#===TPL===
#!/usr/bin/env python
# coding: utf-8

# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/

import sys, os, re, subprocess, urllib2, time, traceback, codecs, hashlib, base64
from getopt import getopt, GetoptError

acceptedExtensions = {
  '.txt': True,
}
ignore = {
  'rules_for_KSafe.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Plus_Rules.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
  'rules_for_360.txt': True,
  'rules_for_ESET[1].txt': True,
  'rules_for_ESET[2].txt': True,
  'rules_for_Kaspersky.txt': True,
  
}
verbatim = {
  'COPYING': True,
}

def combineSubscriptions(sourceDir, targetDir, timeout=30):
  global acceptedExtensions, ignore, verbatim

  if not os.path.exists(targetDir):
    os.makedirs(targetDir, 0755)

  known = {}
  for file in os.listdir(sourceDir):
    if file in ignore or file[0] == '.' or not os.path.isfile(os.path.join(sourceDir, file)):
      continue
    if file in verbatim:
      processVerbatimFile(sourceDir, targetDir, file)
    elif not os.path.splitext(file)[1] in acceptedExtensions:
      continue
    else:
      try:
        processSubscriptionFile(sourceDir, targetDir, file, timeout)
      except:
        print >>sys.stderr, '错误处理订阅文件 "%s"' % file
        traceback.print_exc()
        print >>sys.stderr
      known['rules_for_TPL.tpl'] = True
    known[file] = True


  for file in os.listdir(targetDir):
    if file[0] == '.':
      continue
    if not file in known:
      os.remove(os.path.join(targetDir, file))

def conditionalWrite(filePath, data):
  changed = True
  if os.path.exists(filePath):
    handle = codecs.open(filePath, 'rb', encoding='utf-8')
    oldData = handle.read()
    handle.close()

    checksumRegExp = re.compile(r'^.*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n', re.M | re.I)
    oldData = re.sub(checksumRegExp, '', oldData)
    oldData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', oldData)
    newData = re.sub(checksumRegExp, '', data)
    newData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', newData)
    if oldData == newData:
      changed = False
  if changed:
    handle = codecs.open(filePath, 'wb', encoding='utf-8')
    handle.write(data)
    handle.close()
    

def processVerbatimFile(sourceDir, targetDir, file):
  handle = codecs.open(os.path.join(sourceDir, file), 'rb', encoding='utf-8')
  conditionalWrite(os.path.join(targetDir, file), handle.read())
  handle.close()

def processSubscriptionFile(sourceDir, targetDir, file, timeout):
  filePath = os.path.join(sourceDir, file)
  handle = codecs.open(filePath, 'rb', encoding='utf-8')
  lines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
  handle.close()

  header = ''
  if len(lines) > 0:
    header = lines[0]
    del lines[0]
  if not re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', header, re.I):
    raise Exception('这是不是一个有效的Adblock Plus的订阅文件。')

  lines = resolveIncludes(filePath, lines, timeout)
  lines = filter(lambda l: l != '' and not re.search(r'!\s*checksum[\s\-:]+([\w\+\/=]+)', l, re.I), lines)

  writeTPL(os.path.join(targetDir, 'rules_for_TPL.tpl'), lines)

  checksum = hashlib.md5()
  checksum.update((header + '\n' + '\n'.join(lines) + '\n').encode('utf-8'))
  lines.insert(0, '! Checksum: %s' % re.sub(r'=', '', base64.b64encode(checksum.digest())))
  lines.insert(0, header)
  conditionalWrite(os.path.join(targetDir, file), '\n'.join(lines) + '\n')

def resolveIncludes(filePath, lines, timeout, level=0):
  if level > 5:
    raise Exception('有太多的嵌套包含，这可能是循环引用的地方。')

  result = []
  for line in lines:
    match = re.search(r'^\s*%include\s+(.*)%\s*$', line)
    if match:
      file = match.group(1)
      newLines = None
      if re.match(r'^https?://', file):
        result.append('! *** Fetched from: %s ***' % file)

        request = urllib2.urlopen(file, None, timeout)
        charset = 'utf-8'
        contentType = request.headers.get('content-type', '')
        if contentType.find('charset=') >= 0:
          charset = contentType.split('charset=', 1)[1]
        newLines = unicode(request.read(), charset).split('\n')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), newLines)
        newLines = filter(lambda l: not re.search(r'^\s*!.*?\bExpires\s*(?::|after)\s*(\d+)\s*(h)?', l, re.M | re.I), newLines)
      else:
        result.append('! *** %s ***' % file)

        parentDir = os.path.dirname(filePath)
        includePath = os.path.join(parentDir, file)
        relPath = os.path.relpath(includePath, parentDir)
        if len(relPath) == 0 or relPath[0] == '.':
          raise Exception('无效包括 "%s", 需要是一个 HTTP/HTTPS 地址或一个相对文件路径' % file)

        handle = codecs.open(includePath, 'rb', encoding='utf-8')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
        newLines = resolveIncludes(includePath, newLines, timeout, level + 1)
        handle.close()

      if len(newLines) and re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        del newLines[0]
      result.extend(newLines)
    else:
      if line.find('%timestamp%') >= 0:
        if level == 0:
          line = line.replace('%timestamp%', time.strftime('%d %b %Y %H:%M UTC', time.gmtime()))
        else:
          line = ''
      result.append(line)
  return result

def writeTPL(filePath, lines):
  result = []
  result.append('msFilterList')
  for line in lines:
    if re.search(r'^!', line):
      # This is a comment. Handle "Expires" comment in a special way, keep the rest.
      match = re.search(r'\bExpires\s*(?::|after)\s*(\d+)\s*(h)?', line, re.I)
      if match:
        interval = int(match.group(1))
        if match.group(2):
          interval = int(interval / 24)
        result.append(': Expires=%i' % interval)
      else:
        result.append(re.sub(r'!', '#', re.sub(r'--!$', '--#', line)))
    elif line.find('#') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    
    else:
      #把domain给删掉
      line = re.sub(r'\$domain=[^,]*,','', line)
      line = re.sub(r'\$domain=[^,]*$','', line)
      # We have a blocking or exception rule, try to convert it
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = line[2:]

      hasUnsupportedOptions = False
      requiresScript = False
      match = re.search(r'^(.*?)\$(.*)', line)
      if match:
        # This rule has options, check whether any of them are important
        line = match.group(1)
        options = match.group(2).replace('_', '-').lower().split(',')

        # A number of options are not supported in MSIE but can be safely ignored, remove them
        options = filter(lambda o: not o in ('', 'third-party', '~third-party', 'match-case', '~match-case', '~object-subrequest', '~other', '~donottrack'), options)

        # Also ignore domain negation of whitelists
        if isException:
          options = filter(lambda o: not o.startswith('domain=~'), options)

        if 'donottrack' in options:
          # Rules with donottrack option should always be removed
          hasUnsupportedOptions = True
          
        unsupportedOptions = 0
        
        if 'object-subrequest' in options:
          # The rule applies to object subrequests, which may not be filtered by TPLs
          unsupportedOptions += 1
        if 'elemhide' in options:
          # The rule prevents the hiding of elements, which is not possible with TPLs
          unsupportedOptions += 1
          
        if unsupportedOptions >= len(options):
          # The rule only applies to unsupported options
          hasUnsupportedOptions = True
        else:
          # The rule has other significant options that need to be evaluated
          if 'script' in options and (len(options) - unsupportedOptions) == 1:
            # Mark rules that only apply to scripts for approximate conversion
            requiresScript = True
          else:
            # The rule has further options that aren't available in TPLs.
            # Unless an exception rule is specific to a domain, all remaining
            # options are ignored to avoid potential false positives.
            if isException:
              hasDomain = any([o.startswith('domain=') for o in options])
            else:
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:
        # Do not include filters with unsupported options
        
        result.append('# ' + origLine)
      else:
        line = line.replace('^', '/') # Assume that separator placeholders mean slashes

        # Try to extract domain info
        domain = None
        match = re.search(r'^(\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # No domain info, remove anchors at the rule start
          line = re.sub(r'^\|\|', 'http://', line)
          line = re.sub(r'^\|', '', line)
          
        # Remove anchors at the rule end
        line = re.sub(r'\|$', '', line)
        # Remove unnecessary asterisks at the ends of lines
        line = re.sub(r'\*$', '', line)
        # Emulate $script by appending *.js to the rule
        if requiresScript:
          line += '*.js'
        if line.startswith('/*'):
          line = line[2:]
        if domain:
          line = '%sd %s %s' % ('+' if isException else '-', domain, line)
          line = re.sub(r'\s+/$', '', line)
          result.append(line)
        elif isException:
          # Exception rules without domains are unsupported
          result.append('# ' + origLine)
        else:
          result.append('- ' + line)
  conditionalWrite(filePath, '\n'.join(result) + '\n')

def usage():
  print '''Usage: %s [source_dir] [output_dir]

Options:
  -h          --help              Print this message and exit
  -t seconds  --timeout=seconds   Timeout when fetching remote subscriptions
''' % os.path.basename(sys.argv[0])

if __name__ == '__main__':
  try:
    opts, args = getopt(sys.argv[1:], 'ht:', ['help', 'timeout='])
  except GetoptError, e:
    print str(e)
    usage()
    sys.exit(2)

  sourceDir, targetDir =  '.', 'Temp'
  if len(args) >= 1:
    sourceDir = args[0]
  if len(args) >= 2:
    targetDir = args[1]

  timeout = 30
  for option, value in opts:
    if option in ('-h', '--help'):
      usage()
      sys.exit()
    elif option in ('-t', '--timeout'):
      timeout = int(value)

  if os.path.exists(os.path.join(sourceDir, '.hg')):
    # Our source is a Mercurial repository, try updating
    subprocess.Popen(['hg', '-R', sourceDir, 'pull', '--update']).communicate()

  combineSubscriptions(sourceDir, targetDir, timeout)
#把临时生成的文件移动回根目录
import shutil
import os
if os.path.isfile('.' + 'rules_for_TPL.tpl'):
  os.system('rm -fr rules_for_TPL.tpl')
else:
  shutil.copy('./Temp/rules_for_TPL.tpl', '.')

#===AB Pro===
#!/usr/bin/env python
# coding: utf-8

# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/

import sys, os, re, subprocess, urllib2, time, traceback, codecs, hashlib, base64
from getopt import getopt, GetoptError


acceptedExtensions = {
  '.txt': True,
}
ignore = {
  'rules_for_KSafe.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Plus_Rules.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
  'rules_for_360.txt': True,
  'rules_for_ESET[1].txt': True,
  'rules_for_ESET[2].txt': True,
  'rules_for_Kaspersky.txt': True,
  
}
verbatim = {
  'COPYING': True,
}

def combineSubscriptions(sourceDir, targetDir, timeout=30):
  global acceptedExtensions, ignore, verbatim

  if not os.path.exists(targetDir):
    os.makedirs(targetDir, 0755)

  known = {}
  for file in os.listdir(sourceDir):
    if file in ignore or file[0] == '.' or not os.path.isfile(os.path.join(sourceDir, file)):
      continue
    if file in verbatim:
      processVerbatimFile(sourceDir, targetDir, file)
    elif not os.path.splitext(file)[1] in acceptedExtensions:
      continue
    else:
      try:
        processSubscriptionFile(sourceDir, targetDir, file, timeout)
      except:
        print >>sys.stderr, '错误处理订阅文件 "%s"' % file
        traceback.print_exc()
        print >>sys.stderr
      known['rules_for_AB_PRO.txt'] = True
    known[file] = True

  for file in os.listdir(targetDir):
    if file[0] == '.':
      continue
    if not file in known:
      os.remove(os.path.join(targetDir, file))


def conditionalWrite(filePath, data):
  changed = True
  if os.path.exists(filePath):
    handle = codecs.open(filePath, 'rb', encoding='utf-8')
    oldData = handle.read()
    handle.close()

    checksumRegExp = re.compile(r'^.*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n', re.M | re.I)
    oldData = re.sub(checksumRegExp, '', oldData)
    oldData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', oldData)
    newData = re.sub(checksumRegExp, '', data)
    newData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', newData)
    if oldData == newData:
      changed = False
  if changed:
    handle = codecs.open(filePath, 'wb', encoding='utf-8')
    handle.write(data)
    handle.close()
    

def processVerbatimFile(sourceDir, targetDir, file):
  handle = codecs.open(os.path.join(sourceDir, file), 'rb', encoding='utf-8')
  conditionalWrite(os.path.join(targetDir, file), handle.read())
  handle.close()

def processSubscriptionFile(sourceDir, targetDir, file, timeout):
  filePath = os.path.join(sourceDir, file)
  handle = codecs.open(filePath, 'rb', encoding='utf-8')
  lines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
  handle.close()

  header = ''
  if len(lines) > 0:
    header = lines[0]
    del lines[0]
  if not re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', header, re.I):
    raise Exception('这是不是一个有效的Adblock Plus的订阅文件。')

  lines = resolveIncludes(filePath, lines, timeout)
  lines = filter(lambda l: l != '' and not re.search(r'!\s*checksum[\s\-:]+([\w\+\/=]+)', l, re.I), lines)

  writeRule(os.path.join(targetDir, 'rules_for_AB_PRO.txt'), lines)

  checksum = hashlib.md5()
  checksum.update((header + '\n' + '\n'.join(lines) + '\n').encode('utf-8'))
  lines.insert(0, '! Checksum: %s' % re.sub(r'=', '', base64.b64encode(checksum.digest())))
  lines.insert(0, header)
  conditionalWrite(os.path.join(targetDir, file), '\n'.join(lines) + '\n')

def resolveIncludes(filePath, lines, timeout, level=0):
  if level > 5:
    raise Exception('有太多的嵌套包含，这可能是循环引用的地方。')


  result = []
  for line in lines:
    match = re.search(r'^\s*%include\s+(.*)%\s*$', line)
    if match:
      file = match.group(1)
      newLines = None
      if re.match(r'^https?://', file):
        result.append('! *** Fetched from: %s ***' % file)


        charset = 'utf-8'
        contentType = request.headers.get('content-type', '')
        if contentType.find('charset=') >= 0:
          charset = contentType.split('charset=', 1)[1]
        newLines = unicode(request.read(), charset).split('\n')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), newLines)
      else:
        result.append('! *** %s ***' % file)

        parentDir = os.path.dirname(filePath)
        includePath = os.path.join(parentDir, file)
        relPath = os.path.relpath(includePath, parentDir)
        if len(relPath) == 0 or relPath[0] == '.':
          raise Exception('无效包括 "%s", 需要是一个 HTTP/HTTPS 地址或一个相对文件路径' % file)

        handle = codecs.open(includePath, 'rb', encoding='utf-8')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
        newLines = resolveIncludes(includePath, newLines, timeout, level + 1)
        handle.close()
        


	  
        
      if len(newLines) and re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        del newLines[0]
      result.extend(newLines)
  
    else:
      if line.find('%timestamp%') >= 0:
        if level == 0:
          line = line.replace('%timestamp%', time.strftime('%d %b %Y %H:%M UTC', time.gmtime()))
        else:
          line = ''
      result.append(line)
  return result

def writeRule(filePath, lines):
  result = []
  for line in lines:
    if re.search(r'^!', line):
      #生成版本号
      match = re.search(ur'(?<=版本_)(\d\.)*\d', line, re.I)
      if match:
        vs = line[4:9]
        vs = re.sub(r'\.','', vs)
        #vs = int(vs)
        vs = 'version=%s' % vs       
        
      # 其他注释去除。
      if line.find(r'!\-+.*$') >= 0:
        pass
      '''result.append(re.sub(r'!\-+.*$', '',  line))
    if re.search(r'\n\s*\n', lines):
      result.append(re.sub(r'\n\s*\n', '',  lines))'''
    elif line.find('#') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    elif line.find('@@') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    else:
      # We have a blocking or exception rule, try to convert it
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = line[2:]

        

      hasUnsupportedOptions = False
      requiresScript = False
      match = re.search(r'^(.*?)\$(.*)', line)
      if match:
        # This rule has options, check whether any of them are important
        line = match.group(1)
        options = match.group(2).replace('_', '-').lower().split(',')

        # A number of options are not supported in MSIE but can be safely ignored, remove them
        options = filter(lambda o: not o in ('', 'third-party', '~third-party', 'match-case', '~match-case', '~object-subrequest', '~other', '~donottrack'), options)

        # Also ignore domain negation of whitelists
        if isException:
          options = filter(lambda o: not o.startswith('domain=~'), options)

        if 'donottrack' in options:
          # Rules with donottrack option should always be removed
          hasUnsupportedOptions = True
          
        unsupportedOptions = 0
        
        if 'object-subrequest' in options:
          # The rule applies to object subrequests, which may not be filtered by TPLs
          unsupportedOptions += 1
        if 'elemhide' in options:
          # The rule prevents the hiding of elements, which is not possible with TPLs
          unsupportedOptions += 1
          
        if unsupportedOptions >= len(options):
          # The rule only applies to unsupported options
          hasUnsupportedOptions = True
        else:
          # The rule has other significant options that need to be evaluated
          if 'script' in options and (len(options) - unsupportedOptions) == 1:
            # Mark rules that only apply to scripts for approximate conversion
            requiresScript = True
          else:
            # The rule has further options that aren't available in TPLs.
            # Unless an exception rule is specific to a domain, all remaining
            # options are ignored to avoid potential false positives.
            if isException:
              hasUnsupportedOptions = any([o.startswith('domain=') for o in options])
            else:
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:
        # 不包括不支持的选项的过滤器
        origLine = re.sub(r'^\|\|', '', origLine)
        origLine = re.sub(r'^\|', '', origLine)
        origLine = re.sub(r'\$.*$','', origLine)
        #去掉http://
        if origLine.startswith('http://'):
          origLine = origLine[7:] #前面一个数字是上一行字符串的字符数
        result.append('5,4,' + origLine)
      else:
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        match = re.search(r'^(\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 没有域名信息，删除规则头的标记
          line = re.sub(r'^\|\|', '', line)
          line = re.sub(r'^\|', '', line)
        # 删除规则尾的标记
        line = re.sub(r'\|$', '', line)
        # 删除不必要的两端的管状符
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          line += '*.js'
        if line.startswith('http://'):
          line = line[7:] #前面一个数字是上一行字符串的字符数
        if domain:
          line = '%s%s%s' % ('+' if isException else '', domain, line)
          line = re.sub(r'\s+/$', '', line)
          result.append(line)
        elif isException:
          # 没有域的例外规则不受支持
          result.append('!' + origLine)
        else:
          result.append('' + line)
  #标识
  top = u'[General]'
  
  #规则头
  head = u'''name=广告过滤软件通用强效广告过滤规则 for AB Pro
updateUrl=http://adfiltering-rules.googlecode.com/svn/trunk/lastest/rules_for_AB_PRO.txt
updateTime=1
[Whitelist]
[Block Address]
Copyright 2011 xcffl, Apache License 2.0
'''
  #规则尾
  bottom = '[Block Object]'
  #输出到文件  
  conditionalWrite(filePath, top + '\r\n' + vs + '\r\n' + head +  '\r\n'.join(result) + '\r\n' + bottom)

def usage():
  print '''Usage: %s [source_dir] [output_dir]

Options:
  -h          --help              Print this message and exit
  -t seconds  --timeout=seconds   Timeout when fetching remote subscriptions
''' % os.path.basename(sys.argv[0])

if __name__ == '__main__':
  try:
    opts, args = getopt(sys.argv[1:], 'ht:', ['help', 'timeout='])
  except GetoptError, e:
    print str(e)
    usage()
    sys.exit(2)

  sourceDir, targetDir =  '.', 'Temp'
  if len(args) >= 1:
    sourceDir = args[0]
  if len(args) >= 2:
    targetDir = args[1]


  timeout = 30
  for option, value in opts:
    if option in ('-h', '--help'):
      usage()
      sys.exit()
    elif option in ('-t', '--timeout'):
      timeout = int(value)

  if os.path.exists(os.path.join(sourceDir, '.hg')):
    # Our source is a Mercurial repository, try updating
    subprocess.Popen(['hg', '-R', sourceDir, 'pull', '--update']).communicate()


    
  combineSubscriptions(sourceDir, targetDir, timeout)

  #笔记：(#|!)\-+[^\-]*\n    匹配无效分类
  #     (#|!)\-+【广告强效过滤规则.* 匹配第一行规则标题
#把换行符替换为;并把临时生成的文件移动回根目录

'''#读取文件
file1 = open("./Temp/rules_for_AB_PRO.txt","r")
#file2 = open("rules_for_AB_PRO.txt","w")
#把换行符替换为;
#sp = re.compile('\n+') 
rules = file1.readlines() #读取全部内容
rules = ';'.join(rules)
rules = rules ,

file1 = open("./Temp/rules_for_AB_PRO.txt","w")

file1.write(rules)
file1.close()
#file2.close()'''

#把临时生成的文件移动回根目录
import shutil
import os
if os.path.isfile('.' + 'rules_for_AB_PRO.txt'):
  os.system('rm -fr rules_for_AB_PRO.txt')
else:
  shutil.copy('./Temp/rules_for_AB_PRO.txt', '.')

#===ESET+Kaspersky===
#!/usr/bin/env python
# coding: utf-8

# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/

import sys, os, re, subprocess, urllib2, time, traceback, codecs, hashlib, base64
from getopt import getopt, GetoptError


acceptedExtensions = {
  '.txt': True,
}
ignore = {
  'rules_for_KSafe.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Plus_Rules.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
  'rules_for_360.txt': True,
  'rules_for_ESET[1].txt': True,
  'rules_for_ESET[2].txt': True,
  'rules_for_Kaspersky.txt': True,
  
}
verbatim = {
  'COPYING': True,
}

def combineSubscriptions(sourceDir, targetDir, timeout=30):
  global acceptedExtensions, ignore, verbatim

  if not os.path.exists(targetDir):
    os.makedirs(targetDir, 0755)

  known = {}
  for file in os.listdir(sourceDir):
    if file in ignore or file[0] == '.' or not os.path.isfile(os.path.join(sourceDir, file)):
      continue
    if file in verbatim:
      processVerbatimFile(sourceDir, targetDir, file)
    elif not os.path.splitext(file)[1] in acceptedExtensions:
      continue
    else:
      try:
        processSubscriptionFile(sourceDir, targetDir, file, timeout)
      except:
        print >>sys.stderr, '错误处理订阅文件 "%s"' % file
        traceback.print_exc()
        print >>sys.stderr
      known['rules_for_Kaspersky.txt'] = True
    known[file] = True

  for file in os.listdir(targetDir):
    if file[0] == '.':
      continue
    if not file in known:
      os.remove(os.path.join(targetDir, file))


def conditionalWrite(filePath, data):
  changed = True
  if os.path.exists(filePath):
    handle = codecs.open(filePath, 'rb', encoding='utf-8')
    oldData = handle.read()
    handle.close()

    checksumRegExp = re.compile(r'^.*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n', re.M | re.I)
    oldData = re.sub(checksumRegExp, '', oldData)
    oldData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', oldData)
    newData = re.sub(checksumRegExp, '', data)
    newData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', newData)
    if oldData == newData:
      changed = False
  if changed:
    handle = codecs.open(filePath, 'wb', encoding='utf-8')
    handle.write(data)
    handle.close()
    

def processVerbatimFile(sourceDir, targetDir, file):
  handle = codecs.open(os.path.join(sourceDir, file), 'rb', encoding='utf-8')
  conditionalWrite(os.path.join(targetDir, file), handle.read())
  handle.close()

def processSubscriptionFile(sourceDir, targetDir, file, timeout):
  filePath = os.path.join(sourceDir, file)
  handle = codecs.open(filePath, 'rb', encoding='utf-8')
  lines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
  handle.close()

  header = ''
  if len(lines) > 0:
    header = lines[0]
    del lines[0]
  if not re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', header, re.I):
    raise Exception('这是不是一个有效的Adblock Plus的订阅文件。')

  lines = resolveIncludes(filePath, lines, timeout)
  lines = filter(lambda l: l != '' and not re.search(r'!\s*checksum[\s\-:]+([\w\+\/=]+)', l, re.I), lines)

  writeRule(os.path.join(targetDir, 'rules_for_Kaspersky.txt'), lines)

  checksum = hashlib.md5()
  checksum.update((header + '\n' + '\n'.join(lines) + '\n').encode('utf-8'))
  lines.insert(0, '! Checksum: %s' % re.sub(r'=', '', base64.b64encode(checksum.digest())))
  lines.insert(0, header)
  conditionalWrite(os.path.join(targetDir, file), '\n'.join(lines) + '\n')

def resolveIncludes(filePath, lines, timeout, level=0):
  if level > 5:
    raise Exception('有太多的嵌套包含，这可能是循环引用的地方。')


  result = []
  for line in lines:
    match = re.search(r'^\s*%include\s+(.*)%\s*$', line)
    if match:
      file = match.group(1)
      newLines = None
      if re.match(r'^https?://', file):
        result.append('! *** Fetched from: %s ***' % file)


        charset = 'utf-8'
        contentType = request.headers.get('content-type', '')
        if contentType.find('charset=') >= 0:
          charset = contentType.split('charset=', 1)[1]
        newLines = unicode(request.read(), charset).split('\n')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), newLines)
      else:
        result.append('! *** %s ***' % file)

        parentDir = os.path.dirname(filePath)
        includePath = os.path.join(parentDir, file)
        relPath = os.path.relpath(includePath, parentDir)
        if len(relPath) == 0 or relPath[0] == '.':
          raise Exception('无效包括 "%s", 需要是一个 HTTP/HTTPS 地址或一个相对文件路径' % file)

        handle = codecs.open(includePath, 'rb', encoding='utf-8')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
        newLines = resolveIncludes(includePath, newLines, timeout, level + 1)
        handle.close()
        


	  
        
      if len(newLines) and re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        del newLines[0]
      result.extend(newLines)
  
    else:
      if line.find('%timestamp%') >= 0:
        if level == 0:
          line = line.replace('%timestamp%', time.strftime('%d %b %Y %H:%M UTC', time.gmtime()))
        else:
          line = ''
      result.append(line)
  return result

def writeRule(filePath, lines):
  result = []
  for line in lines:
    if re.search(r'^!', line):
      # 这是注释，去除。
      if line.find(r'!\-+.*$') >= 0:
        pass
      '''result.append(re.sub(r'!\-+.*$', '',  line))
    if re.search(r'\n\s*\n', lines):
      result.append(re.sub(r'\n\s*\n', '',  lines))'''
    elif line.find('#') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    elif line.find('@@') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    else:
      # We have a blocking or exception rule, try to convert it
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = line[2:]

        

      hasUnsupportedOptions = False
      requiresScript = False
      match = re.search(r'^(.*?)\$(.*)', line)
      if match:
        # This rule has options, check whether any of them are important
        line = match.group(1)
        options = match.group(2).replace('_', '-').lower().split(',')

        # A number of options are not supported in MSIE but can be safely ignored, remove them
        options = filter(lambda o: not o in ('', 'third-party', '~third-party', 'match-case', '~match-case', '~object-subrequest', '~other', '~donottrack'), options)

        # Also ignore domain negation of whitelists
        if isException:
          options = filter(lambda o: not o.startswith('domain=~'), options)

        if 'donottrack' in options:
          # Rules with donottrack option should always be removed
          hasUnsupportedOptions = True
          
        unsupportedOptions = 0
        
        if 'object-subrequest' in options:
          # The rule applies to object subrequests, which may not be filtered by TPLs
          unsupportedOptions += 1
        if 'elemhide' in options:
          # The rule prevents the hiding of elements, which is not possible with TPLs
          unsupportedOptions += 1
          
        if unsupportedOptions >= len(options):
          # The rule only applies to unsupported options
          hasUnsupportedOptions = True
        else:
          # The rule has other significant options that need to be evaluated
          if 'script' in options and (len(options) - unsupportedOptions) == 1:
            # Mark rules that only apply to scripts for approximate conversion
            requiresScript = True
          else:
            # The rule has further options that aren't available in TPLs.
            # Unless an exception rule is specific to a domain, all remaining
            # options are ignored to avoid potential false positives.
            if isException:
              hasUnsupportedOptions = any([o.startswith('domain=') for o in options])
            else:
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:
        # 不包括不支持的选项的过滤器
        origLine = re.sub(r'^\|\|', '', origLine)
        origLine = re.sub(r'^\|', '', origLine)
        origLine = re.sub(r'\$.*$','', origLine)
        #去掉http://
        if origLine.startswith('http://'):
          origLine = origLine[7:] #前面一个数字是上一行字符串的字符数
        result.append(origLine)
      else:
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        match = re.search(r'^(\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 没有域名信息，删除规则头的标记
          line = re.sub(r'^\|\|', '', line)
          line = re.sub(r'^\|', '', line)
        # 删除规则尾的标记
        line = re.sub(r'\|$', '', line)
        # 删除不必要的两端的管状符
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          line += '*.js'
        #去掉http://
        if line.startswith('http://'):
          line = line[7:] #前面一个数字是上一行字符串的字符数
        if domain:
          line = '%s%s%s' % ('+' if isException else '', domain, line)
          line = re.sub(r'\s+/$', '', line)
          result.append(line)
        elif isException:
          # 没有域的例外规则不受支持
          result.append('!' + origLine)
        else:
          result.append('' + line)
  conditionalWrite(filePath, '\r\n'.join(result) + '\r\n')

def usage():
  print '''Usage: %s [source_dir] [output_dir]

Options:
  -h          --help              Print this message and exit
  -t seconds  --timeout=seconds   Timeout when fetching remote subscriptions
''' % os.path.basename(sys.argv[0])

if __name__ == '__main__':
  try:
    opts, args = getopt(sys.argv[1:], 'ht:', ['help', 'timeout='])
  except GetoptError, e:
    print str(e)
    usage()
    sys.exit(2)

  sourceDir, targetDir =  '.', 'Temp'
  if len(args) >= 1:
    sourceDir = args[0]
  if len(args) >= 2:
    targetDir = args[1]


  timeout = 30
  for option, value in opts:
    if option in ('-h', '--help'):
      usage()
      sys.exit()
    elif option in ('-t', '--timeout'):
      timeout = int(value)

  if os.path.exists(os.path.join(sourceDir, '.hg')):
    # Our source is a Mercurial repository, try updating
    subprocess.Popen(['hg', '-R', sourceDir, 'pull', '--update']).communicate()


    
  combineSubscriptions(sourceDir, targetDir, timeout)

  #笔记：(#|!)\-+[^\-]*\n    匹配无效分类
  #     (#|!)\-+【广告强效过滤规则.* 匹配第一行规则标题

#由于ESET文件限制，因此分成2个版本
#生成ESET版
#2000行1个文件
genera_rules_file = open('./Temp/rules_for_Kaspersky.txt','r')
eset1_file = open('rules_for_ESET[1].txt','w')
eset2_file = open('rules_for_ESET[2].txt','w')

genera_rules = genera_rules_file.readlines()
eset1 = genera_rules[0:1999]
eset1 = ''.join(eset1)
print >> eset1_file, eset1
eset2 = genera_rules[2000:]
eset2 = ''.join(eset2)
print >> eset2_file, eset2

eset1_file.close()
eset2_file.close()
genera_rules_file.close()

#把卡巴斯基版移动回根目录
import shutil
import os
if os.path.isfile('.' + 'rules_for_Kaspersky.txt'):
  os.system('rm -fr rules_for_Kaspersky.txt')
else:
  shutil.copy('./Temp/rules_for_Kaspersky.txt', '.')

#===360===
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 需要Python和Pywin32(http://superb-sea2.dl.sourceforge.net/project/pywin32/pywin32/Build%20217/pywin32-217.win32-py2.7.exe)
# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/

import sys, os, re, subprocess, urllib2, time, traceback, codecs, hashlib, base64
from getopt import getopt, GetoptError

acceptedExtensions = {
  '.txt': True,
}
ignore = {
  'rules_for_KSafe.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Plus_Rules.txt': True,
  'rules_for_AB_PRO.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
  'rules_for_360.txt': True,
  'rules_for_ESET[1].txt': True,
  'rules_for_ESET[2].txt': True,
  'rules_for_Kaspersky.txt': True,
  
}
verbatim = {
  'COPYING': True,
}

def combineSubscriptions(sourceDir, targetDir, timeout=30):
  global acceptedExtensions, ignore, verbatim

  if not os.path.exists(targetDir):
    os.makedirs(targetDir, 0755)

  known = {}
  for file in os.listdir(sourceDir):
    if file in ignore or file[0] == '.' or not os.path.isfile(os.path.join(sourceDir, file)):
      continue
    if file in verbatim:
      processVerbatimFile(sourceDir, targetDir, file)
    elif not os.path.splitext(file)[1] in acceptedExtensions:
      continue
    else:
      try:
        processSubscriptionFile(sourceDir, targetDir, file, timeout)
      except:
        print >>sys.stderr, '错误处理订阅文件 "%s"' % file
        traceback.print_exc()
        print >>sys.stderr
      known['rules_for_360.txt'] = True
    known[file] = True


  for file in os.listdir(targetDir):
    if file[0] == '.':
      continue
    if not file in known:
      os.remove(os.path.join(targetDir, file))

def conditionalWrite(filePath, data):
  changed = True
  if os.path.exists(filePath):
    handle = codecs.open(filePath, 'rb', encoding='utf-8')
    oldData = handle.read()
    handle.close()

    checksumRegExp = re.compile(r'^.*!\s*checksum[\s\-:]+([\w\+\/=]+).*\n', re.M | re.I)
    oldData = re.sub(checksumRegExp, '', oldData)
    oldData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', oldData)
    newData = re.sub(checksumRegExp, '', data)
    newData = re.sub(r'\s*\d+ \w+ \d+ \d+:\d+ UTC', '', newData)
    if oldData == newData:
      changed = False
  if changed:
    handle = codecs.open(filePath, 'wb', encoding='utf-8')
    handle.write(data)
    handle.close()
    

def processVerbatimFile(sourceDir, targetDir, file):
  handle = codecs.open(os.path.join(sourceDir, file), 'rb', encoding='utf-8')
  conditionalWrite(os.path.join(targetDir, file), handle.read())
  handle.close()

def processSubscriptionFile(sourceDir, targetDir, file, timeout):
  filePath = os.path.join(sourceDir, file)
  handle = codecs.open(filePath, 'rb', encoding='utf-8')
  lines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
  handle.close()

  header = ''
  if len(lines) > 0:
    header = lines[0]
    del lines[0]
  if not re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', header, re.I):
    raise Exception('这是不是一个有效的Adblock Plus的订阅文件。')

  lines = resolveIncludes(filePath, lines, timeout)
  lines = filter(lambda l: l != '' and not re.search(r'!\s*checksum[\s\-:]+([\w\+\/=]+)', l, re.I), lines)

  writeRule(os.path.join(targetDir, 'rules_for_360.txt'), lines)

  checksum = hashlib.md5()
  checksum.update((header + '\n' + '\n'.join(lines) + '\n').encode('utf-8'))
  lines.insert(0, '! Checksum: %s' % re.sub(r'=', '', base64.b64encode(checksum.digest())))
  lines.insert(0, header)
  conditionalWrite(os.path.join(targetDir, file), '\n'.join(lines) + '\n')

def resolveIncludes(filePath, lines, timeout, level=0):
  if level > 5:
    raise Exception('有太多的嵌套包含，这可能是循环引用的地方。')

  result = []
  for line in lines:
    match = re.search(r'^\s*%include\s+(.*)%\s*$', line)
    if match:
      file = match.group(1)
      newLines = None
      if re.match(r'^https?://', file):
        result.append('! *** Fetched from: %s ***' % file)

        request = urllib2.urlopen(file, None, timeout)
        charset = 'utf-8'
        contentType = request.headers.get('content-type', '')
        if contentType.find('charset=') >= 0:
          charset = contentType.split('charset=', 1)[1]
        newLines = unicode(request.read(), charset).split('\n')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), newLines)
        newLines = filter(lambda l: not re.search(r'^\s*!.*?\bExpires\s*(?::|after)\s*(\d+)\s*(h)?', l, re.M | re.I), newLines)
      else:
        result.append('! *** %s ***' % file)

        parentDir = os.path.dirname(filePath)
        includePath = os.path.join(parentDir, file)
        relPath = os.path.relpath(includePath, parentDir)
        if len(relPath) == 0 or relPath[0] == '.':
          raise Exception('无效包括 "%s", 需要是一个 HTTP/HTTPS 地址或一个相对文件路径' % file)

        handle = codecs.open(includePath, 'rb', encoding='utf-8')
        newLines = map(lambda l: re.sub(r'[\r\n]', '', l), handle.readlines())
        newLines = resolveIncludes(includePath, newLines, timeout, level + 1)
        handle.close()

      if len(newLines) and re.search(r'\[Adblock(?:\s*Plus\s*([\d\.]+)?)?\]', newLines[0], re.I):
        del newLines[0]
      result.extend(newLines)
    else:
      if line.find('%timestamp%') >= 0:
        if level == 0:
          line = line.replace('%timestamp%', time.strftime('%d %b %Y %H:%M UTC', time.gmtime()))
        else:
          line = ''
      result.append(line)
  return result

def writeRule(filePath, lines):
  result = []
  for line in lines:
    if re.search(r'^!', line):
      #把各种注释内容替换掉
      #line = re.sub(r'(#|!)\-+[^\-]*$','', line)
      line = re.sub(r'^!.*$','', line)
      #由于猎豹有些问题，暂时使用短名称
      #line = re.sub('for ABP', 'for liebao', line)
      result.append(line)
    elif line.find('#') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    elif line.find('@@') >= 0:
      # Element hiding rules are not supported in MSIE, drop them
      pass
    else:
      # We have a blocking or exception rule, try to convert it
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = line[2:]

        

      hasUnsupportedOptions = False
      requiresScript = False
      match = re.search(r'^(.*?)\$(.*)', line)
      if match:
        # This rule has options, check whether any of them are important
        line = match.group(1)
        options = match.group(2).replace('_', '-').lower().split(',')

        # A number of options are not supported in MSIE but can be safely ignored, remove them
        options = filter(lambda o: not o in ('', 'third-party', '~third-party', 'match-case', '~match-case', '~object-subrequest', '~other', '~donottrack'), options)

        # Also ignore domain negation of whitelists
        if isException:
          options = filter(lambda o: not o.startswith('domain=~'), options)

        if 'donottrack' in options:
          # Rules with donottrack option should always be removed
          hasUnsupportedOptions = True
          
        unsupportedOptions = 0
        
        if 'object-subrequest' in options:
          # The rule applies to object subrequests, which may not be filtered by TPLs
          unsupportedOptions += 1
        if 'elemhide' in options:
          # The rule prevents the hiding of elements, which is not possible with TPLs
          unsupportedOptions += 1
          
        if unsupportedOptions >= len(options):
          # The rule only applies to unsupported options
          hasUnsupportedOptions = True
        else:
          # The rule has other significant options that need to be evaluated
          if 'script' in options and (len(options) - unsupportedOptions) == 1:
            # Mark rules that only apply to scripts for approximate conversion
            requiresScript = True
          else:
            # The rule has further options that aren't available in TPLs.
            # Unless an exception rule is specific to a domain, all remaining
            # options are ignored to avoid potential false positives.
            if isException:
              hasUnsupportedOptions = any([o.startswith('domain=') for o in options])
            else:
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:
        # 不包括不支持的选项的过滤器
        origLine = re.sub(r'^\|\|', '', origLine)
        origLine = re.sub(r'^\|', '', origLine)
        origLine = re.sub(r'\$d.*$','', origLine)
        #去掉http://
        if origLine.startswith('http://'):
          origLine = origLine[7:] #前面一个数字是上一行字符串的字符数
        result.append('http://' + origLine)
      else:
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        match = re.search(r'^(\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 没有域名信息，删除规则头的标记
          line = re.sub(r'^\|\|', '', line)
          line = re.sub(r'^\|', '', line)
        # 删除规则尾的标记
        line = re.sub(r'\|$', '', line)
        # 删除不必要的两端的管状符
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          line += '*.js*'
        if line.startswith('http://'):
          line = line[7:] #前面一个数字是上一行字符串的字符数
        if domain:
          line = 'http://%s%s%s' % ('+' if isException else '', domain, line)
          line = re.sub(r'\s+/$', '', line)
          result.append(line)
        elif isException:
          # 没有域的例外规则不受支持
          result.append('!' + origLine)
        else:
          result.append('http://' + line)
  conditionalWrite(filePath, '\n'.join(result) + '\n')

def usage():
  print '''Usage: %s [source_dir] [output_dir]

Options:
  -h          --help              Print this message and exit
  -t seconds  --timeout=seconds   Timeout when fetching remote subscriptions
''' % os.path.basename(sys.argv[0])

if __name__ == '__main__':
  try:
    opts, args = getopt(sys.argv[1:], 'ht:', ['help', 'timeout='])
  except GetoptError, e:
    print str(e)
    usage()
    sys.exit(2)

  sourceDir, targetDir =  '.', 'Temp'
  if len(args) >= 1:
    sourceDir = args[0]
  if len(args) >= 2:
    targetDir = args[1]


  timeout = 30
  for option, value in opts:
    if option in ('-h', '--help'):
      usage()
      sys.exit()
    elif option in ('-t', '--timeout'):
      timeout = int(value)

  if os.path.exists(os.path.join(sourceDir, '.hg')):
    # Our source is a Mercurial repository, try updating
    subprocess.Popen(['hg', '-R', sourceDir, 'pull', '--update']).communicate()


    
  combineSubscriptions(sourceDir, targetDir, timeout)

  #笔记：(#|!)\-+[^\-]*\n    匹配无效分类
  #     (#|!)\-+【广告强效过滤规则.* 匹配第一行规则标题
#把临时生成的文件移动回根目录
'''import shutil
import os
if os.path.isfile('.' + 'rules_for_360.txt'):
  os.system('rm -fr rules_for_360.txt')
else:
  shutil.copy('./Temp/rules_for_360.txt', '.')'''
#把临时生成的文件移动回根目录，同时去除所有的空白行
# coding=utf-8
file1 = open("./Temp/rules_for_360.txt","r")
file2 = open("rules_for_360.txt","w")
while 1:
 text = file1.readline()
 if( text == '' ):
  print ""
  break
 elif( text != '\n'):
  file2.write( text )
file1.close()
file2.close()


#获取当前路径
import os
path = os.getcwd()
#360临时规则的路径
path = path + 'rules_for_360.txt'
#读取规则
rulefile = open('rules_for_360.txt', 'r')
rules360 = rulefile.readlines()
rules360 = ''.join(rules360)
rulefile.close()
#复制360规则到剪贴板
import win32clipboard as wincb
import win32con
wincb.OpenClipboard()
wincb.EmptyClipboard()
wincb.SetClipboardData(win32con.CF_TEXT, rules360)
wincb.CloseClipboard()
#删除360规则临时文件
tempfile ='rules_for_360.txt'   
os.remove(tempfile)
#打开360更新网站
import os
os.startfile('http://rules.wd.360.cn/upload_rule_22.html?pid=60546&id=105545')

#===把加入校验的ABP版移回根目录===
import shutil
import os
if os.path.isfile('.' + 'rules_for_ABP.txt'):
  os.system('rm -fr rules_for_ABP.txt')
else:
  shutil.copy('./Temp/rules_for_ABP.txt', '.')  


#===删除临时文件夹===
import os, stat;  
root_dir = r'.';  
def walk(path):  
  for item in os.listdir(path):  
    subpath = os.path.join(path, item);  
    mode = os.stat(subpath)[stat.ST_MODE];  
               
    if stat.S_ISDIR(mode):  
      if item=="Temp":  
        print "Clean %s ..." % subpath;  
        print "%d deleted!" % purge(subpath);  
      else:  
        walk(subpath);  
      
def purge(path):  
  count = 0;  
  for item in os.listdir(path):  
    subpath = os.path.join(path, item);  
    mode = os.stat(subpath)[stat.ST_MODE];  
    if stat.S_ISDIR(mode):  
      count += purge(subpath);  
    else:  
      os.chmod(subpath, stat.S_IREAD|stat.S_IWRITE);  
      os.unlink(subpath);  
      count += 1;  
  os.rmdir(path);  
  count += 1;  
  return count;            
if __name__=='__main__':  
  walk(root_dir);  
