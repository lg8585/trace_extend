set PM=procmon.exe
set BrowserPath="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
set StartPage=about:blank
del monitor.pml
del monitor.xml
del startup.json
del shutdown.json
start %PM% /quiet /minimized /backingfile monitor.pml /LoadConfig procmon_config/chrome-file.pmc
%PM% /waitforidle
ping 127.0.0.1 -n 5 >nul
start /wait "" %BrowserPath% %StartPage% --trace-startup --trace-startup-duration=10 --trace-shutdown --trace-startup-file=%~dp0startup.json --trace-shutdown-file=%~dp0shutdown.json
%PM% /terminate
%PM% /LoadConfig procmon_config/chrome-file.pmc /Openlog monitor.pml /SaveAs monitor.xml
python trace_analyze\merge_procmon_to_trace.py --startup-file=%~dp0startup.json --shutdown-file=%~dp0shutdown.json --procmon-file=%~dp0monitor.xml --output-file=out.json
pause