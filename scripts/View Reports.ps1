Add-Type -AssemblyName System.IO.Compression.FileSystem

$Path = "C:\inetpub\Reports\"
$files = Get-ChildItem $Path -File

if(Test-Path -Path "$Path\archived"){
    Remove-Item "$Path\archived"
    Start-Process "C:\Program Files\LibreOffice\program\soffice.exe"
    Start-Sleep 20
}

foreach($file in $files){
    $buffer = New-Object byte[] 4
    $fileStream = [System.IO.File]::OpenRead($file.FullName)
    $fileStream.Read($buffer, 0, 4) > ""
    $fileStream.Close()

    $signature = -join ($buffer | ForEach-Object { $_.ToString("X2") })
    
    if($signature -eq "504B0304"){ # is a ziptype.
        
        $tempFolder = [System.IO.Path]::GetTempPath() + [System.IO.Path]::GetRandomFileName()
        New-Item -ItemType Directory -Path $tempFolder | Out-Null
        
        [System.IO.Compression.ZipFile]::ExtractToDirectory($file.FullName, $tempFolder)

        if (Test-Path "$tempFolder\content.xml") {
            try { Stop-Process -Name soffice.bin -Force } catch {}
            Start-Process "C:\Program Files\LibreOffice\program\soffice.exe" "--headless -view $($file.FullName)"
            Start-Sleep 10
            Stop-Process -Name soffice.bin -Force
        }
        Remove-Item -Recurse -Force $tempFolder
    }

    Remove-Item $file.FullName
}




