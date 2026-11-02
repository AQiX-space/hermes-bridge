# Requires Windows PowerShell 5.1. Explicit -Apply is mandatory for any change.
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$PublicKeyFile,
  [switch]$Apply,
  [string]$AuthorizedKeysPath = 'C:\ProgramData\ssh\administrators_authorized_keys'
)
$ErrorActionPreference = 'Stop'
$keyLine = (Get-Content -LiteralPath $PublicKeyFile -Raw -ErrorAction Stop).Trim()
if ($keyLine -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?$') { throw 'Invalid Ed25519 public key format' }
$parts=$keyLine -split ' ',3
$bytes=[Convert]::FromBase64String($parts[1])
if($bytes.Length -ne 51){throw 'Unexpected Ed25519 key encoding'}
$prefix=[byte[]](0,0,0,11,115,115,104,45,101,100,50,53,53,49,57,0,0,0,32)
for($i=0;$i -lt $prefix.Length;$i++){if($bytes[$i] -ne $prefix[$i]){throw 'Invalid Ed25519 key encoding'}}
$fingerprint='SHA256:'+([Convert]::ToBase64String([Security.Cryptography.SHA256]::Create().ComputeHash($bytes)).TrimEnd('='))
# Do not follow a reparse point (symlink/junction). Avoid touching unrecognized user paths.
$canonical='C:\ProgramData\ssh\administrators_authorized_keys'
if([IO.Path]::GetFullPath($AuthorizedKeysPath) -ne $canonical){throw 'Unsupported authorized_keys path'}
if(Test-Path -LiteralPath $AuthorizedKeysPath){
 $file=Get-Item -LiteralPath $AuthorizedKeysPath -Force
 if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Refusing reparse point'}
 $existing=@(Get-Content -LiteralPath $AuthorizedKeysPath)
}else{$existing=@()}
$matches=@($existing|Where-Object {($_ -split ' ',3).Count -ge 2 -and ($_ -split ' ',3)[1] -eq $parts[1]})
if($matches.Count -gt 0){Write-Output "ALREADY_AUTHORIZED $fingerprint";exit 0}
if(-not $Apply){Write-Output "MISSING_OPERATOR_KEY $fingerprint; DRY_RUN_NO_CHANGE";exit 2}
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=New-Object Security.Principal.WindowsPrincipal($id)
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Administrator elevation required'}
$parent=Split-Path -Parent $AuthorizedKeysPath
if(-not (Test-Path -LiteralPath $parent)){throw 'OpenSSH system directory is missing'}
$stamp=(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
$backup=$AuthorizedKeysPath+'.backup-'+$stamp
$previouslyExists=Test-Path -LiteralPath $AuthorizedKeysPath
if($previouslyExists){Copy-Item -LiteralPath $AuthorizedKeysPath -Destination $backup -ErrorAction Stop}
try {
 $added=@($existing)+@($parts[0]+' '+$parts[1]+$(if($parts.Count -eq 3){' '+$parts[2]}else{''}))
 [IO.File]::WriteAllLines($AuthorizedKeysPath,[string[]]$added,(New-Object System.Text.UTF8Encoding($false)))
 # Windows OpenSSH admin keys must be limited to Administrators and SYSTEM.
 & icacls.exe $AuthorizedKeysPath /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
 if($LASTEXITCODE -ne 0){throw 'icacls failed'}
 Write-Output "OPERATOR_KEY_INSTALLED $fingerprint; BACKUP=$backup"
} catch {
 if(Test-Path -LiteralPath $backup){Copy-Item -LiteralPath $backup -Destination $AuthorizedKeysPath -Force}
 elseif(-not $previouslyExists -and (Test-Path -LiteralPath $AuthorizedKeysPath)){Remove-Item -LiteralPath $AuthorizedKeysPath -Force}
 throw
}
