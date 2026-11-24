param([Parameter(Mandatory=$true)][string]$ScriptFile)
$ErrorActionPreference='Stop'
$install=Get-Content -LiteralPath $ScriptFile -Raw
if ($install -notmatch ';exit 0\s*$') {throw 'OpenSSH install script is missing success status'}
$install=$install -replace ';exit 0\s*$',''
function Get-WindowsCapability {
  [CmdletBinding()]param([switch]$Online,[string]$Name)
  return [pscustomobject]@{State=$(if($script:installed){'Installed'}else{'NotPresent'})}
}
function Add-WindowsCapability {
  [CmdletBinding()]param([switch]$Online,[string]$Name)
  $script:add++
  $script:installed=$true
  if($script:createRule){$script:rule=[pscustomobject]@{Enabled='True'}}
  if($script:createService){$script:service=[pscustomobject]@{Status='Running';StartupType='Automatic'}}
  return [pscustomobject]@{RestartNeeded=$false}
}
function Get-NetFirewallRule {
  [CmdletBinding()]param([string]$Name)
  return $script:rule
}
function Disable-NetFirewallRule {
  [CmdletBinding()]param([string]$Name)
  $script:disable++
  if($script:failDisable){throw 'Test: disabling new rule denied'}
  $script:rule.Enabled='False'
}
function Get-Service {
  [CmdletBinding()]param([string]$Name)
  return $script:service
}
function Stop-Service {
  [CmdletBinding()]param([string]$Name)
  $script:stop++
  $script:service.Status='Stopped'
}
function Set-Service {
  [CmdletBinding()]param([string]$Name,[string]$StartupType)
  $script:set++
  $script:service.StartupType=$StartupType
}
function Reset-Mock {
  $script:installed=$false;$script:rule=$null;$script:service=$null
  $script:createRule=$true;$script:createService=$true;$script:failDisable=$false
  $script:add=0;$script:disable=0;$script:stop=0;$script:set=0
}
Reset-Mock
Invoke-Expression $install
if(!$script:installed -or $script:rule.Enabled -ne 'False' -or $script:service.Status -ne 'Stopped' -or $script:service.StartupType -ne 'Manual' -or $script:disable -ne 1 -or $script:stop -ne 1 -or $script:set -ne 1){throw 'New SSH server did not remain disabled/inaccessible'}
Write-Output 'PASS: newly installed SSH server rule disabled and service not running'
Reset-Mock
$script:installed=$true;$script:rule=[pscustomobject]@{Enabled='True'};$script:service=[pscustomobject]@{Status='Running';StartupType='Automatic'}
Invoke-Expression $install
if($script:add -ne 0 -or $script:disable -ne 0 -or $script:stop -ne 0 -or $script:set -ne 0){throw 'Existing SSH installation was altered'}
Write-Output 'PASS: already installed and running SSH service preserved'
Reset-Mock
$script:rule=[pscustomobject]@{Enabled='True'};$script:service=[pscustomobject]@{Status='Running';StartupType='Automatic'}
Invoke-Expression $install
if($script:disable -ne 0 -or $script:stop -ne 0 -or $script:set -ne 0){throw 'Pre-existing SSH firewall/service was altered'}
Write-Output 'PASS: pre-existing SSH access preserved during feature installation'
Reset-Mock
$script:failDisable=$true
$threw=$false
try{Invoke-Expression $install}catch{$threw=$true}
if(!$threw){throw 'Failed to enforce firewall rule did not stop installer'}
Write-Output 'PASS: firewall disable error fails closed'
