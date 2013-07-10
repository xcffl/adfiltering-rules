# -*- coding: utf-8 -*-
print 'Processing,please wait for about 15 second...'
#===读取额外规则===
import re
exfile = open('extra.dat', 'r')
exrule = exfile.read()
exrule = exrule.split('[')
tplall = exrule[1]
tplall = tplall.split('\n')
urlall = exrule[2]
urlall = urlall.split('\n')
exfile.close()
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
  'rules_for_ADSafe.txt': True,
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
  for line in lines:
    #对优酷不作处理
    
    if re.search(r'^!', line):
      #把各种注释内容替换掉
      #line = re.sub(r'(#|!)\-+[^\-]*$','', line)
      line = re.sub('^\s*!.*?\bExpires\s*(?::|after)\s*(\d+)\s*(h)?', '', line)
      line = re.sub('^! Redirect:.*$','', line)
      line = re.sub(r'(.*?)\Expires(.*)', '', line)
      #line = re.sub('!Title:.*$', '!Title:adfiltering-rules', line)
      #由于猎豹有些问题，暂时使用短名称
      #line = re.sub('for ABP', 'for liebao', line)
      line = re.sub(r'--!$', '--!', line)
      line = re.sub(u'!Description:一个通用、全面的广告过滤规则', u'''!Version:1.0
!Description:一个通用、全面的广告过滤规则
!Url:http://rules.adfiltering-rules.asia/svn/trunk/lastest/rules_for_liebao.txt''', line)
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
          if times == 3:
            for dm in cut:
              dm1 = cut[0]
              dm2 = cut[1]
              dm3 = cut[2]

            
            line = '''###%s	$d=%s\r\n###%s	$d=%s\r\n###%s	$d=%s''' %(eh,dm1,eh,dm2,eh,dm3)
            


          
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
          if times == 3:
            for dm in cut:
              dm1 = cut[0]
              dm2 = cut[1]
              dm3 = cut[2]

            
            line = '''##%s	$d=%s\r\n##%s	$d=%s\r\n##%s	$d=%s''' %(eh,dm1,eh,dm2,eh,dm3)
            

            
            
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
        line = line[2:] + '$w'

        
      # 尝试提取域名信息
      domain = None
      match = re.search(r'^(\|\||\|w+://[^*:/]+:\d+?)(/.*)', line)
      if match:
        
        domain = match.group(1)
        line = match.group(2)
      else:
        
        # 修改各种标记
        #优酷不处理
        '''if re.search(r'youku',line):
          line = '''''
        if re.search(r'\$', line):
          #先分类，分成非选项和过滤规则选项
          dotmatch = re.search(r'^([^$\s]+)(\s*)(\S*)$', line)
          dotdomain = dotmatch.group(1)            
          dotother = dotmatch.group(3)                                
          #先像普通规则那样处理非选项
          dotdomain = re.sub(r'\.', '\.', dotdomain)
          dotdomain = re.sub(r'^\|(?!\|)', '^' ,dotdomain)
          dotdomain = re.sub(r'\|$', '$' ,dotdomain)
          dotdomain = re.sub(r'\/', '\/', dotdomain)            
          dotdomain = re.sub(r'^\*', '', dotdomain)
          dotdomain = re.sub(r'\*$', '', dotdomain)
          dotdomain = re.sub(r'\*', '\*', dotdomain)            
          dotdomain = re.sub(r'\?', '\?', dotdomain)
          dotdomain = re.sub(r'^\|\|', ':\/\/([^\/]+\.)?', dotdomain)
          #再处理过滤规则选项                                 
          dotother = re.sub('object-subrequest', 'object', dotother)
          dotother = re.sub('subdocument', 'document', dotother)
          dotother = re.sub('subdocument', 'document', dotother)                                 
          dotother = re.sub(',', '|', dotother)  
          if re.search(',', dotother):
            othermatch = re.search(r'^(.+)([,$]domain=[a-z0-9~.]+)(.*)$', dotother)#选择符部分，domain要单独处理，其他的放到$t=
            if othermatch:
              fst =  othermatch.group(1)
              domain = othermatch.group(2)
              sec =  othermatch.group(3)
              other = fst + sec
              other = re.sub(r'^[$,]', ',', other)
              other = re.sub(r',$', '|', other)
              other = '$t=' + other
              domain = '$d' + domain[7:]#嘛，现在只支持一个域名。
              dotother = other + ',' + domain
          if re.search(r'\$.*\$', dotother):
            dotother = re.sub(r'\$w', ',$w', dotother)
            dotother = re.sub(r'\$domain', '$d', dotother)
            dotother = '	' + dotother
          
          
          line = '/' + dotdomain + '/' + dotother
          
        else:
          line = re.sub(r'\.', '\.', line)
          line = re.sub(r'^\|(?!\|)', '^' ,line)
          line = re.sub(r'\|$', '$' ,line)
          line = re.sub(r'\/', '\/', line)
          line = re.sub(r'\*', '\*', line)
          line = re.sub(r'\?', '\?', line)
          line = re.sub(r'^\|\|', ':\/\/([^\/]+\.)?', line)
          line = '/' + line + '/'
        
      # 删除规则尾的标记
      #line = re.sub(r'\|$', '$', line)
      # 删除不必要的两端的管状符


      #猎豹版不用删除http://
      #if line.startswith('http://'): #要删除的规则中的字符串
        #line = line[7:] #前面一个数字是上一行字符串的字符数
      if domain:
        #优酷不处理
        line = '||%s%s' % ( domain, line)
        '''if re.search(r'youku',line):
          line = '''''
        if re.search(r'\$', line):
          #先分类，分成非选项和过滤规则选项
          dotmatch = re.search(r'^([^$\s]+)(\s*)(\S*)$', line)
          dotdomain = dotmatch.group(1)            
          dotother = dotmatch.group(3)
          #先像普通规则那样处理非选项            
          dotdomain = re.sub(r'\.', '\.', dotdomain)
          dotdomain = re.sub(r'^\|(?!\|)', '^' ,dotdomain)
          dotdomain = re.sub(r'\|$', '$' ,dotdomain)
          dotdomain = re.sub(r'\/', '\/', dotdomain)
          dotdomain = re.sub(r'^\*', '', dotdomain)
          dotdomain = re.sub(r'\*$', '', dotdomain)
          dotdomain = re.sub(r'\*', '\*', dotdomain)
          dotdomain = re.sub(r'\?', '\?', dotdomain)
          dotdomain = re.sub(r'^\|\|', ':\/\/([^\/]+\.)?', dotdomain)
          
          #再处理过滤规则选项                                 
          dotother = re.sub('object-subrequest', 'object', dotother)
          dotother = re.sub('subdocument', 'document', dotother)
          dotother = re.sub('subdocument', 'document', dotother)                                 
          dotother = re.sub(',', '|', dotother)            
          if re.search(',', dotother):
            othermatch = re.search(r'^(.+)([,$]domain=[a-z0-9~.]+)(.*)$', dotother)#选择符部分，domain要单独处理，其他的放到$t=
            if othermatch:
              fst =  othermatch.group(1)
              domain = othermatch.group(2)
              sec =  othermatch.group(3)
              other = fst + sec
              other = re.sub(r'^[$,]', ',', other)
              other = re.sub(r',$', '|', other)
              other = '$t=' + other
              domain = '$d' + domain[7:]#嘛，现在只支持一个域名。
              dotother = other + ',' + domain
          if re.search(r'\$.*\$', dotother):
            dotother = re.sub(r'\$w', ',$w', dotother)
            dotother = re.sub(r'\$domain', '$d', dotother)
            dotother = '	' + dotother            
          line = '/' + dotdomain + '/' + dotother
          

        else:
          line = re.sub(r'\.', '\.', line)
          line = re.sub(r'^\|(?!\|)', '^' ,line)
          line = re.sub(r'\|$', '$' ,line)
          line = re.sub(r'\/', '\/', line)
          line = re.sub(r'\*', '\*', line)
          line = re.sub(r'\?', '\?', line)
          line = re.sub(r'^\|\|', ':\/\/([^\/]+\.)?', line)
          line = '/' + line + '/'   
        result.append(line)
        
      elif isException:        
        
        # 没有域的例外规则
        origLine = origLine[2:] + '$w'
        #优酷不处理
        '''if re.search(r'youku',line):
          line = '''''
        if re.search(r'\$', origLine):
          #先分类，分成非选项和过滤规则选项
          dotmatch = re.search(r'^([^$\s]+)(\s*)(\S*)$', origLine)
          dotdomain = dotmatch.group(1)            
          dotother = dotmatch.group(3)
          #先像普通规则那样处理非选项
          dotdomain = re.sub(r'\.', '\.', dotdomain)
          dotdomain = re.sub(r'^\|(?!\|)', '^' ,dotdomain)
          dotdomain = re.sub(r'\|$', '$' ,dotdomain)
          
          
          dotdomain = re.sub(r'\/', '\/', dotdomain)
          dotdomain = re.sub(r'^\*', '', dotdomain)
          dotdomain = re.sub(r'\*$', '', dotdomain)
          dotdomain = re.sub(r'\*', '\*', dotdomain)
          dotdomain = re.sub(r'\?', '\?', dotdomain)
          dotdomain = re.sub(r'^\|\|', ':\/\/([^\/]+\.)?', dotdomain)
          #再处理过滤规则选项                                 
          dotother = re.sub('object-subrequest', 'object', dotother)
          dotother = re.sub('subdocument', 'document', dotother)
          dotother = re.sub('subdocument', 'document', dotother)                                 
          dotother = re.sub(',', '|', dotother)  
          if re.search(',', dotother):
            othermatch = re.search(r'^(.+)([,$]domain=[a-z0-9~.]+)(.*)$', dotother)#选择符部分，domain要单独处理，其他的放到$t=
            if othermatch:
              fst =  othermatch.group(1)
              domain = othermatch.group(2)
              sec =  othermatch.group(3)
              other = fst + sec
              other = re.sub(r'^[$,]', ',', other)
              other = re.sub(r',$', '|', other)
              other = '$t=' + other
              domain = '$d' + domain[7:]#嘛，现在只支持一个域名。
              dotother = other + ',' + domain
          if re.search(r'\$.*\$', dotother):
            dotother = re.sub(r'\$w', ',$w', dotother)
            dotother = re.sub(r'\$domain', '$d', dotother)
            dotother = '	' + dotother
          origLine = '/' + dotdomain + '/' + dotother
          
        else:
          origLine = re.sub('.', '\.', origLine)
          origLine = re.sub(r'^\|(?!\|)', '^' ,origLine)
          origLine = re.sub(r'\|$', '$' ,origLine)
          origLine = re.sub('/', '\/', origLine)
          origLine = re.sub(r'\*', '\*', origLine)
          origLine = re.sub('?', '\?', origLine)
          origLine = re.sub(r'^\|\|', ':\/\/([^\/]+\.)?', origLine)
          origLine = '/' + origLine + '/'
          
        result.append(origLine)
      else:
        #处理到这里基本就是通用规则的处置了
        #line = re.sub(r'^\/\/$','', '/' + line + '/')
        

        
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
  'rules_for_ADSafe.txt': True,
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
  for line in lines:
    if re.search(r'\$domain\=', line):#先行处理domain规则
      dmatch = re.search(r'^([^$]*)(.*)$', line)
      if re.search('~', line):
        line = dmatch.group(1)        
      else:
        line = ''
  top = u'''Opera Preferences version 2.1\r\n
; Do not edit this file while Opera is running\r\n
; This file is stored in UTF-8 encoding\r\n'''
  result.append(top)
  for line in lines:
    if re.search(r'^!', line):
      # 这是注释，前面的去除。
      if re.search(r'\!Updated:.*$', line):
        line = re.sub('!', '; ', line)
      elif re.search(r'Expires',line):
        line = ''
       
      else:
        line = re.sub(r'\!', '; ', line)
        line = re.sub(r'; Copyright 2011-2013 Adfiltering-Rules Project, Apache License 2.0','; Copyright 2011-2013 Adfiltering-Rules Project, Apache License 2.0\r\n[prefs]\r\nprioritize excludelist=1\r\n[include]\r\n*\r\n[exclude]\r\n', line)
      result.append(line)

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
        origLine = re.sub(r'^\|\|', 'http://', origLine)
        origLine = re.sub(r'^\|', '', origLine)
        origLine = re.sub(r'\$.*$','', origLine)
        #以*开头的不处理，其余加http://
        if origLine.startswith('*'):
          origLine = origLine #前面一个数字是上一行字符串的字符数
        else:
          origLine = "http://" + origLine #前面一个数字是上一行字符串的字符数
        result.append('' + origLine)
      else:
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        #Opera版部分规则要http://前缀
        line = re.sub(r'^\|\|', 'http://', line)
        line = re.sub(r'^\|', '', line)
        match = re.search(r'^(\|\||\|\w+://)([^*:/]+)(:\d+)?(/.*)', line)
        if match:
          domain = match.group(2)
          line = match.group(4)
        else:
          # 没有域名信息，删除规则头的标记
          line = re.sub(r'^\|\|', 'http://', line)
          line = re.sub(r'^\|', '', line)
        # 删除规则尾的标记
        line = re.sub(r'\|$', '', line)
        # 删除不必要的两端的管状符
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          line += '*.js'
        #以*开头的不处理，其余加http://
        if origLine.startswith('*'):
          origLine = origLine #前面一个数字是上一行字符串的字符数
        else:
          origLine = "http://" + origLine #前面一个数字是上一行字符串的字符数
        if domain:
          print domain
          line = '%s%s%s' % ('+' if isException else '', domain, line)
          line = re.sub(r'\s+/$', '', line)
          result.append(line)
        elif isException:
          # 没有域的例外规则不受支持
          result.append('!' + origLine)
        else:
          result.append('' + line)
  urlfilter = ''
  for line in urlall:
    if re.search(r'[^\]]$',line):
      urlfilter = urlfilter + line + '\n'

  conditionalWrite(filePath, '\r\n'.join(result) + '\r\n' + urlfilter)

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
#把临时生成的文件移动回根目录，同时去除所有的空白行
# coding=utf-8
file1 = open("./Temp/urlfilter.ini","r")
file2 = open("urlfilter.ini","w")
while 1:
 text = file1.readline()
 if( text == '' ):
  
  break
 elif( text != '\n'):
   if text!= '\n':
     file2.write( text )
file1.close()
file2.close()
  
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
  'rules_for_ADSafe.txt': True,
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
  tplrule = ''
  for line in tplall:
    if re.search(r'[^\]]$',line):
      tplrule = tplrule + line + '\n'
  conditionalWrite(filePath, '\n'.join(result) + '\n' + tplrule)

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

  
#===Avast!===
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
  'rules_for_ADSafe.txt': True,
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
    if re.search(r'\$domain\=', line):#先行处理domain规则
      dmatch = re.search(r'^([^$]*)(.*)$', line)
      if re.search('~', line):
        line = dmatch.group(1)        
      else:
        line = ''
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
  head = '''[WebScanner]\r\nHttpRedirectPort=80,8080,8091,8081,8008,8888,3124,3127,3128\r\nHttpRedirectPortUpdated1=1\r\nURLBlocking=1\r\nIgnoreAddress=\r\nIgnoreLocalhost=1\r\nExcludedTypes=1\r\nExcludedTypesList=image/gif;image/png;audio/*;video/*\r\nExcludedURLs=0\r\nHttpScanParamFlag=1\r\nIntelligentStreamScanning=1\r\nWebScanning=1\r\nBlockedURLs='''
  #规则尾
  bottom = '''[Common]\r\nProviderEnabled=1\r\nOverwriteReport=0\r\nPUPAction=abort\r\nReport=TXT\r\nReportName=*\r\nReportRecords=Infected;HardErrors;SoftErrors\r\nScanFullFiles=0\r\nScanPUP=0\r\nScanPackers=All\r\nShowAppliedActionNotification=1\r\nSuspiciousAction=abort\r\nTaskSensitivity=100\r\nUseCodeEmulation=1\r\nVirusAction=abort'''
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
  'rules_for_ADSafe.txt': True,
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
      known['rules_for_AB_PRO.ini'] = True
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

  writeRule(os.path.join(targetDir, 'rules_for_AB_PRO.ini'), lines)

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
    if re.search(r'\$domain\=', line):#先行处理domain规则
      dmatch = re.search(r'^([^$]*)(.*)$', line)
      if re.search('~', line):
        line = dmatch.group(1)        
      else:
        line = ''
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
  head = u'''name=Adfiltering-Rules for AB Pro\r\nupdateUrl=http://rules.adfiltering-rules.asia/svn/trunk/lastest/rules_for_AB_PRO.ini\r\nupdateTime=1\r\n[Whitelist]\r\n规则主页：http://www.afrules.tk/\r\n隶属于Adfiltering-Rules项目，如需帮助或了解详情\r\n请访问 https://code.google.com/p/adfiltering-rules/\r\nCopyright 2011-2013 Adfiltering-Rules Project, Apache License 2.0\r\n[Block Address]\r\n'''
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
file1 = open("./Temp/rules_for_AB_PRO.ini","r")
#file2 = open("rules_for_AB_PRO.ini","w")
#把换行符替换为;
#sp = re.compile('\n+') 
rules = file1.readlines() #读取全部内容
rules = ';'.join(rules)
rules = rules ,

file1 = open("./Temp/rules_for_AB_PRO.ini","w")

file1.write(rules)
file1.close()
#file2.close()'''

#把临时生成的文件移动回根目录
import shutil
import os
if os.path.isfile('.' + 'rules_for_AB_PRO.ini'):
  os.system('rm -fr rules_for_AB_PRO.ini')
else:
  shutil.copy('./Temp/rules_for_AB_PRO.ini', '.')

#===ESET+Kaspersky+瑞星+金山+火绒版===
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
  'rules_for_ADSafe.txt': True,
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
    if re.search(r'\$domain\=', line):#先行处理domain规则
      dmatch = re.search(r'^([^$]*)(.*)$', line)
      if re.search('~', line):
        line = dmatch.group(1)        
      else:
        line = ''
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
          result.append(line)
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
rising_file = open('rules_for_rising.fwr','w')
ks_file = open('rules_for_KSafe.txt','w')
hr_file = open('rules_for_HuoRong.xml','w')

genera_rules = genera_rules_file.readlines()
eset1 = genera_rules[0:1999]
eset1 = ''.join(eset1)
print >> eset1_file, eset1
eset2 = genera_rules[2000:]
eset2 = ''.join(eset2)
print >> eset2_file, eset2

#制作瑞星
print >> rising_file, '<?xml version="1.0" encoding="utf-8"?>\n<Adrule>\n	<open>1</open>\n	<name>广告强效过滤规则</name>\n	<desc>一个通用、全面的广告过滤规则，隶属于adfiltering-rules项目。</desc>\n	<urlrules>'
for line in genera_rules:
  print >> rising_file, '		<rule Type="0" url="' + re.sub(r'\r|\n', '', line) + '"/>'
  
print >> rising_file, '	</urlrules>\n</Adrule>'

#金山版
for line in genera_rules:
  # 优酷临时特殊规则
  line = re.sub(r'f\.youku\.com\/player\/getFlvPath\/fileid\/0\*\?K\=\*.*$', 'f.youku.com/player/get*lv*ath/fileid/*-*-*-*-*?*=*', line)
  line = re.sub(r'static\.youku\.com\/\*\/index\/js\/hzClick\.js', 'static.youku.com/*/index/js/hz*lick.js', line)
  print >> ks_file,'5,4,' +  re.sub(r'\r|\n', '', line)

#火绒版
print >> hr_file,'<?xml version="1.0" encoding="UTF-8"?>\n<rule>'
for line in genera_rules:  
  print >> hr_file,'<analyzer>\n<type>Http</type>\n<path>' + re.sub(r'\r|\n', '', line) + '</path>\n<object>*</object>\n</analyzer>'
print >> hr_file,'</rule>'

  
eset1_file.close()
eset2_file.close()
genera_rules_file.close()
rising_file.close()
ks_file.close()
hr_file.close()

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
  'rules_for_ADSafe.txt': True,
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
    if re.search(r'\$domain\=', line):#先行处理domain规则
      dmatch = re.search(r'^([^$]*)(.*)$', line)
      if re.search('~', line):
        line = dmatch.group(1)        
      else:
        line = ''
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
  endresult = []
  for line in result:
    if re.search(r'^http://((([^\/]*\.){2,})|([^\/*]))[^\*/]*\/.*$', line):
      endresult.append(line)
    
  conditionalWrite(filePath, '\n'.join(endresult) + '\n')

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
os.startfile('http://rules.wd.360.cn/upload_rule_11.html?id=60546')

  
#===ADSafe====
#!/usr/bin/env python
# coding: utf-8


# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/


import sys, os, re, subprocess, urllib2, urllib, time, traceback, codecs, hashlib, base64
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
  'rules_for_ADSafe.txt': True,
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
      known['rules_for_ADSafe.txt'] = True
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

  writeRule(os.path.join(targetDir, 'rules_for_ADSafe.txt'), lines)

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
  itemcount = 0 #定义规则条数
  for line in lines:
    if re.search(r'^!', line):
      #把各种注释内容替换掉
      line = re.sub(r'(#|!)\-+[^\-]*$','', line)
      line = re.sub('^\s*!.*?\bExpires\s*(?::|after)\s*(\d+)\s*(h)?', '', line)
      line = re.sub('^! Redirect:.*$','', line)
      line = re.sub(r'(.*?)\expires(.*)', '', line)
      if re.search(r'\!Title:.*', line):
        line = re.sub(r'\!Title:.*', u'!*title=广告强效过滤规则', line)
        
        '''title = '广告强效过滤规则'
        title = title.encode('mbcs','ignore')
        urllib.quote(line)
        line = line + title'''

      
      line = re.sub('!Author:', '!*author=', line)
      #由于猎豹有些问题，暂时使用短名称
      #line = re.sub('for ABP', 'for liebao', line)
      line = re.sub(r'--!$', '--!', line)
      line = re.sub(r'\!Description:.*$', '', line)
      line = re.sub(r'!Updated:', u'!*lastmodify=', line)
      line = re.sub(r'\!Expires', u'!*itemcount=\r\n!*headend\r\n!Expires', line)
      result.append(line)
    elif line.find('#') >= 0:
      itemcount = itemcount + 1
      # 如果是元素隐藏规则 
      #没域名的全局规则ADSafe不支持 暂时，带排除规则的不支持   
      if re.search(r'(^#)|(~)', line):        
        line = ''
      #有域名的调转域名位置
      #域名排除规则先变成排除
      else:
        #如果只有1个.，就判定要过滤下面子域名
        if re.search(r'^[^\.]*\.[^\.]*#', line):
          line = '%' + line
        #'##'=@@        
        line = re.sub(r'(?<!#)##(?!(\.)|(#))', '@@', line)
        if re.search(r'#[^\.]+(\..+\.)|(\[.+\[)',line):
          line = re.sub(r'###','@@#',line)
        result.append(line)
        #其他不改





    else:
      itemcount = itemcount + 1
      # 有一个例外规则，尝试将其转换
      origLine = line

      isException = False
      if line[0:2] == '@@':
        isException = True
        line = '~' + line[2:]
        

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
           else:
              hasUnsupportedOptions = True

      if hasUnsupportedOptions:        
        # 包括不支持的选项的过滤器（即包含domain的过滤规则)
        #Adsafe暂不支持domain~的排除规则，删掉排除
        origLine = re.sub(r'\|~[^|]+(?=\|)', '', origLine)
        origLine = re.sub(r'\|~[^|]+$', '', origLine)
        origLine = re.sub(r'\$domain=~[^|]+$', '', origLine)
        origLine = re.sub(r'^@@', '~', origLine)
        origLine = re.sub(r'\|\|', '|', origLine)
	#让多domain的地址由英文逗号分割
        if re.search(r'\$domain\=.*\|', origLine):
          l_a = origLine.split('$domain=')
          rule_a = l_a[0]
          dms_a = l_a[1]
          rule_a = re.sub(r'\*$','',rule_a)
          dm_a = dms_a.split('|')
          dms_a = ','.join(dm_a)
          origLine = rule_a + '::' + dms_a
        origLine = re.sub(r'\$domain=', '::', origLine)
        origLine = re.sub(r'\|http:\/\/\*', '*', origLine)
        origLine = re.sub(r'\|http:\/\/', '|', origLine)
        origLine = re.sub(r'（^(|)*\*）|(\*$)','',origLine)#前后星号去掉
        if re.search(r'\.js', origLine):
          origLine = origLine + '$$js'
        else:
          origLine = origLine + '$$auto'
        #origLine = re.sub(r'(?<=\.(gif)|(jpg)|(png)).*','$$image',origLine)
        
        #处理各种规则选项
        if origLine.find('[\$\,]elemhide'):
          pass
                
        result.append(origLine)
      else:
        
        line = line.replace('^', '/*') # 假定分隔符的占位符的意思是斜线

        # 尝试提取域名信息
        domain = None
        match = re.search(r'^(\|\||\|w+://[^*:/]+:\d+)?(/.*)', line)
        if match:
          
          domain = match.group(1)
          line = match.group(2)
        else:

          # 修改各种标记
          #猎豹浏览器暂不支持domain~的排除规则，删掉排除
          #Adsafe暂不支持domain~的排除规则，删掉排除
          line = re.sub(r'\|~[^|]+(?=\|)', '', line)
          line = re.sub(r'\|~[^|]+$', '', line)
          line = re.sub(r'\$domain=~[^|]+$', '', line)
          line = re.sub(r'^@@', '~', line)
          line = re.sub(r'\|\|', '|', line)
          #让多domain的地址由英文逗号分割
          if re.search(r'\$domain\=.*\|', line):
            l_a = line.split('$domain=')
            rule_a = l_a[0]
            dms_a = l_a[1]
            rule_a = re.sub(r'\*$','',rule_a)
            dm_a = dms_a.split('|')
            dms_a = ','.join(dm_a)
            line = rule_a + '::' + dms_a
          line = re.sub(r'\$domain=', '::', line)
          line = re.sub(r'\|http:\/\/\*', '*', line)
          line = re.sub(r'\|http:\/\/', '|', line)
          line = re.sub(r'（^\*）|(\*$)','',line)#前后星号去掉
        # 添加 *.js 到规则以效仿 $script
        if requiresScript:
          
          line += '.js'
	#Ad-Safe版可能需要删除http://
        if line.startswith('http://'): #要删除的规则中的字符串
          line = line[7:] #前面一个数字是上一行字符串的字符数
        if domain:
          #暂不支持domain~的排除规则，删掉排除
          #添加后缀
          line = '|%s%s' % ( domain, line)

          #Adsafe暂不支持domain~的排除规则，删掉排除
          line = re.sub(r'\|~[^|]+(?=\|)', '', line)
          line = re.sub(r'\|~[^|]+$', '', line)
          line = re.sub(r'\$domain=~[^|]+$', '', line)
          line = re.sub(r'^@@', '~', line)
          line = re.sub(r'\|\|', '|', line)          
          #让多domain的地址由英文逗号分割
          if re.search(r'\$domain\=.*\|', line):
            l_a = line.split('$domain=')
            rule_a = l_a[0]            
            dms_a = l_a[1]
            rule_a = re.sub(r'\*$','',rule_a)
            dm_a = dms_a.split('|')
            dms_a = ','.join(dm_a)
            line = rule_a + '::' + dms_a
          line = re.sub(r'\$domain=', '::', line)
          line = re.sub(r'\|http:\/\/\*', '*', line)
          line = re.sub(r'\|http:\/\/', '|', line)
          line = re.sub(r'（^\*）|(\*$)','',line)#前后星号去掉
          if re.search(r'\.js', line):
            line = line + '$$js'
          else:
            line = line + '$$auto'
          result.append(line)
        elif isException:
          # 没有域的例外规则
          #猎豹浏览器暂不支持domain~的排除规则，删掉排除
          #Adsafe暂不支持domain~的排除规则，删掉排除
		  
          origLine = re.sub(r'\|~[^|]+(?=\|)', '', origLine)
          origLine = re.sub(r'\|~[^|]+$', '', origLine)
          origLine = re.sub(r'\$domain=~[^|]+$', '', origLine)
          origLine = re.sub(r'^@@', '~', origLine)
          origLine = re.sub(r'\|\|', '|', origLine)
          #让多domain的地址由英文逗号分割
          if re.search(r'\$domain\=.*\|', origLine):
            l_a = origLine.split('$domain=')
            rule_a = l_a[0]
            dms_a = l_a[1]
            rule_a = re.sub(r'\*$','',rule_a)
            dm_a = dms_a.split('|')
            dms_a = ','.join(dm_a)
            origLine = rule_a + '::' + dms_a
          origLine = re.sub(r'\$domain=', '::', origLine)
          origLine = re.sub(r'\|http:\/\/\*', '*', origLine)
          origLine = re.sub(r'\|http:\/\/', '|', origLine)
          origLine = re.sub(r'（^\*）|(\*$)','',origLine)#前后星号去掉

          if re.search(r'\.js', origLine):
            origLine = origLine + '$$js'
          else:
            origLine = origLine + '$$auto'
          
          result.append(origLine)
    
        else:
          #处理到这里基本就是空白行的处置了
          line = re.sub(r'^\|http:\/\/', '', line)
          if re.search(r'\.js', line):
            line = line + '$$js'
          else:
            line = line + '$$auto'
          result.append(line)
  result = '!*headbegin\r\n' + '\n'.join(result) + '\n'#把结果合并了
  itemcount = str(itemcount)#规则条数转换成字符串
  result = re.sub('itemcount=', 'itemcount=' + itemcount, result)
  conditionalWrite(filePath, result)

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
if os.path.isfile('.' + 'rules_for_ADSafe.txt'):
  os.system('rm -fr rules_for_ADSafe.txt')
else:
  shutil.copy('./Temp/rules_for_ADSafe.txt', '.')'''
#把临时生成的文件移动回根目录，同时去除所有的空白行
# coding=gbk
file1 = open('./Temp/rules_for_ADSafe.txt','r')
file2 = open("rules_for_ADSafe.txt","w")
while 1:
 text = file1.readline()
 if( text == '' ):
  break
 elif( text != '\n'):
  file2.write( text )
file1.close()
file2.close()

#===wallproxy====
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#!/usr/bin/env python
# coding: utf-8


# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/


import sys, os, re, subprocess, urllib2, urllib, time, traceback, codecs, hashlib, base64
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
  'rules_for_ADSafe.txt': True,
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
      known['rules_for_wallproxy.ini'] = True
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

  writeRule(os.path.join(targetDir, 'rules_for_wallproxy.ini'), lines)

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
  itemcount = 0 #定义规则条数
  for line in lines:
    if re.search(r'^!', line):

      result.append(line)
    elif line.find('#') >= 0:
      line = ''
      # 如果是元素隐藏规则 
      #不支持
    else:
      result.append(line)
      
  result = '\n'.join(result) + '\n'#把结果合并了

  conditionalWrite(filePath, result)

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
if os.path.isfile('.' + 'rules_for_wallproxy.ini'):
  os.system('rm -fr rules_for_ADSafe.txt')
else:
  shutil.copy('./Temp/rules_for_wallproxy.ini', '.')'''
#把临时生成的文件移动回根目录，同时去除所有的空白行
# coding=gbk
file1 = open('./Temp/rules_for_wallproxy.ini','r')
file2 = open("rules_for_wallproxy.ini","w")
while 1:
 text = file1.readline()
 if( text == '' ):
  break
 elif( text != '\n'):
  file2.write( text )
file1.close()
file2.close()

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
print 'Finished'
'''#===添加额外规则===
# coding=utf-8
file1 = open('./Temp/rules_for_ADSafe.txt','r')
file2 = open("rules_for_ADSafe.txt","w")'''
