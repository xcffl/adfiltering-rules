@echo off
set TempFile_Name=%SystemRoot%\System32\BatTestUACin_SysRt%Random%.batemp
echo %TempFile_Name%

( echo "BAT Test UAC in Temp" >%TempFile_Name% ) 1>nul 2>nul

if exist %TempFile_Name% (
echo 正在尝试修复过滤规则获取问题……
@echo 203.208.47.1 adfiltering-rules.googlecode.com>>c:\windows\system32\drivers\etc\hosts
echo 已完成，请尝试重新获取规则。
) else (
echo 没有以管理员身份运行当前批处理，无法修复过滤规则获取问题。
)
pause
Rem type %TempFile_Name%
del %TempFile_Name% 1>nul 2>nul
pause >nul
exit