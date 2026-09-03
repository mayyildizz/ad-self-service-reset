<#
.SYNOPSIS
  Creates the least-privilege service account and delegates ONLY what the
  self-service reset needs on one OU. Run on a domain controller (or a machine
  with RSAT) as a Domain Admin, in an elevated PowerShell.

.EXAMPLE
  .\delegate-permissions.ps1 -TargetOU "OU=Staff,DC=corp,DC=example,DC=com" -ServiceAccount svc-pwreset
#>
param(
  [Parameter(Mandatory)] [string] $TargetOU,
  [string] $ServiceAccount = 'svc-pwreset',
  [string] $ServiceAccountOU = ''   # e.g. "OU=Service Accounts,DC=corp,DC=example,DC=com"; default = Users container
)
Import-Module ActiveDirectory
$domain = Get-ADDomain
$upn = "$ServiceAccount@$($domain.DNSRoot)"

if (-not (Get-ADUser -Filter "SamAccountName -eq '$ServiceAccount'" -ErrorAction SilentlyContinue)) {
  $pw = Read-Host -AsSecureString "Password for new service account $upn"
  $params = @{ Name = $ServiceAccount; SamAccountName = $ServiceAccount; UserPrincipalName = $upn
               AccountPassword = $pw; Enabled = $true; PasswordNeverExpires = $true; CannotChangePassword = $true
               Description = 'Self-service password reset (LDAPS). Delegated: Reset Password on target OU only.' }
  if ($ServiceAccountOU) { $params.Path = $ServiceAccountOU }
  New-ADUser @params
  Write-Host "Created $upn"
} else { Write-Host "$upn already exists, reusing it" }

$sid = (Get-ADUser $ServiceAccount).SID
$ouPath = "AD:\$TargetOU"
$acl = Get-Acl $ouPath

# GUIDs from the schema: Reset Password (control access right), lockoutTime and pwdLastSet attributes, user object class.
$ResetPasswordGuid = [Guid]'00299570-246d-11d0-a768-00aa006e0529'
$LockoutTimeGuid   = [Guid]'28630ebf-41d5-11d1-a9c1-0000f80367c1'
$PwdLastSetGuid    = [Guid]'bf967a0a-0de6-11d0-a285-00aa003049e2'
$UserClassGuid     = [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'
$Inherit = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
$Allow   = [System.Security.AccessControl.AccessControlType]::Allow

$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $sid, [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight, $Allow, $ResetPasswordGuid, $Inherit, $UserClassGuid)))
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $sid, [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, $Allow, $LockoutTimeGuid, $Inherit, $UserClassGuid)))
$acl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $sid, [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty, $Allow, $PwdLastSetGuid, $Inherit, $UserClassGuid)))
Set-Acl -Path $ouPath -AclObject $acl

Write-Host ""
Write-Host "Delegated to $upn on $TargetOU :"
Write-Host "  - Reset Password (extended right) on user objects"
Write-Host "  - Write lockoutTime, pwdLastSet on user objects"
Write-Host ""
Write-Host "Put these in .env on the Linux host:"
Write-Host "  AD_BIND_DN=$upn"
Write-Host "  AD_BASE_DN=$TargetOU"
