# -*- coding: utf-8 -*-
#毕业于2012.08.06 v1.0
#增加自动获取时间功能 2012.08.07 v1.1

#先定义原规则各部分，再过滤出chinalist中新规则，分别按顺序打印到文件，再复制回来
import urllib
import re, os
import time
chinalistfile = urllib.urlopen('http://adblock-chinalist.googlecode.com/svn/trunk/adblock-lazy.txt')
chinalist = chinalistfile.read()

#读取afr，合并到同一字符串
afrfile = open('rules_for_ABP.txt', 'r')
afr = afrfile.readlines()
afr = ''.join(afr)

#在需要分割的位置添加标识符\cut/
afr = re.sub(r'!\-{13}.{6}\-{13}(?=\n)','!-------------待分类-------------\cut/', afr)
afr = re.sub('!-------------其他','!-------------其他\cut/', afr)
afr = re.sub('!--------其他--------','!--------其他--------\cut/', afr)

#更新“更新时间”
time = time.strftime("%Y-%m-%d %X", time.localtime())
afr = re.sub(r'(?<=!Updated:).*', time ,afr)

#分割规则
afr = afr.split('\cut/')

#加个atemp
atemp = open('rules_for_ABP.temp.txt', 'w')

#定义各项名称并打印oriRule和oriEH到文件
oriRule = afr[0]
print >> atemp, oriRule
oriEH = afr[1]
print >> atemp, oriEH
oriWL = afr[2]

#chinalist分割
chinalist = chinalist.split('\n')

#过滤出元素隐藏并打印到文件
for line in chinalist:
    if re.search('##', line):        
        isEH = line
        print >> atemp, isEH

#打印oriWL到文件
print >> atemp, oriWL

#过滤出白名单并打印到文件
for line in chinalist:
    if re.search('@@', line):
        isWL = line
        print >> atemp, isWL

afrfile.close()
atemp.close()

#去除空白行,写回原文件
atempfile = open('rules_for_ABP.temp.txt', 'r')
afrfile = open("rules_for_ABP.txt","w")
while 1:
 atemp = atempfile.readline()
 if( atemp == '' ):  
  break
 elif( atemp != '\n'):
  afrfile.write( atemp )
atempfile.close()
afrfile.close()
       


#删除临时文件
atempfile ='rules_for_ABP.temp.txt'   
os.remove(atempfile)
