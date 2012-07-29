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
  'genera_rules.txt': True,
  'Element_Hiding_Rules.txt': True,
  'rules_for_liebao.txt': True,
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
      known['genera_rules.txt'] = True
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

  writeRule(os.path.join(targetDir, 'genera_rules.txt'), lines)

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
        result.append('# ' + origLine)
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
import shutil
import os
if os.path.isfile('.' + 'genera_rules.txt'):
  os.system('rm -fr genera_rules.txt')
else:
  shutil.copy('./Temp/genera_rules.txt', '.')
#删除临时文件夹
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


  
