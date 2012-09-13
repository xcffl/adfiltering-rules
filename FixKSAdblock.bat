@echo off
color 2E
If "%PROCESSOR_ARCHITECTURE%"=="AMD64" (Set b=%SystemRoot%\SysWOW64) Else (Set b=%SystemRoot%\system32)
Rd "%b%\test" >nul 2>nul
Md "%b%\test" 2>nul||(Echo 您使用的是XP以上系统，请使用右键管理员身份运行&&Pause >nul&&Exit)
Rd "%b%\test" >nul 2>nul

echo ===================================================================
echo $ 此规则用来修复金山卫士广告过滤出现的一些问题！
echo ===================================================================
echo $ 比如使用老规则后某些网站出错（如不能播放优酷视频或黑屏）
echo $ 自定义规则包更新时提示已存在等其他一些不明症状。请试试这个东西~~
echo ===================================================================
echo $ 本规则自动判定系统类型，适合XP、VISTA、WIN7。
echo $ 使用VISTA、WIN7系统的请使用管理员运行！
echo ===================================================================
echo $ 注：本规则将清除所有现有规则，使用前请自行备份自定义的规则！切记！！
echo $ Edit By June!
echo ===================================================================
pause

echo.
echo 　　选 1 继续
echo 　　选 2 退出
echo.
set /p p=　请选择:　
if %p%==1 goto FIX
if %p%==2 goto exit

::================= 修复 BUG =====================
:FIX
ver | find "5.1" >nul && if %errorlevel% equ 0 del %systemdrive%\Documents and Settings\All Users\Application Data\kingsoft\kis\kws\adidname.dat && del %systemdrive%\Documents and Settings\All Users\Application Data\kingsoft\kis\kws\blacklist.dat
ver | find "6.1" >nul && if %errorlevel% equ 0 del %systemdrive%\ProgramData\kingsoft\kis\kws\adidname.dat && del %systemdrive%\ProgramData\kingsoft\kis\kws\blacklist.dat
ver | find "6.2" >nul && if %errorlevel% equ 0 del %systemdrive%\ProgramData\kingsoft\kis\kws\adidname.dat && del %systemdrive%\ProgramData\kingsoft\kis\kws\blacklist.dat
echo 已完成，建议先重新启动计算机，再重新订阅/导入规则即可。按任意键结束。
pause >nul
exit

