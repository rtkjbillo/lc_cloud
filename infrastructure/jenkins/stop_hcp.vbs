Set WshShell = WScript.CreateObject("WScript.Shell")

WshShell.AppActivate "hcp"
WScript.Sleep 1000
WshShell.SendKeys "^C"

