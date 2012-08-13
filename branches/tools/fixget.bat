@echo off
set TempFile_Name=%SystemRoot%\System32\BatTestUACin_SysRt%Random%.batemp


( echo "BAT Test UAC in Temp" >%TempFile_Name% ) 1>nul 2>nul

if exist %TempFile_Name% (
echo 本修复工具将重新构建hosts，如果你曾经修改过hosts，请先备份。如果你不了解hosts，那么可以安全地继续。请按任意键继续或点右上角按钮推退出。
pause
echo 正在尝试修复过滤规则获取问题……
@echo off
del %Systemroot%\system32\drivers\etc\hosts
@echo 173.194.72.82 adfiltering-rules.googlecode.com>>%Systemroot%\system32\drivers\etc\hosts
@echo 31.170.163.99 xcffl.tk>>%Systemroot%\system32\drivers\etc\hosts
echo 已完成，请尝试重新获取规则。按任意键结束。
) else (
echo 没有以管理员身份运行当前批处理，无法修复过滤规则获取问题。请按任意键结束。
)
Rem type %TempFile_Name%
del %TempFile_Name% 1>nul 2>nul
pause >nul
exit