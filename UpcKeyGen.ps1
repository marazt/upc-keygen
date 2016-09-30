 <# 
    .SYNOPSIS
    A script for generation of UPC router passwords and connecting to this router.
 
    .DESCRIPTION
    A script for generation of UPC router passwords and connecting to this router.
 
    .PARAMETER ssid
    UPC router ssid, e.g., UPC1234567. Mandatory.
 
	.PARAMETER connect
    Boolean flag if it should try to connect with generated password. Default false.
 
    .EXAMPLE
    Generate passwords: UpcKeyGen.ps1 -ssid UPC1234567
	Generate passwords and try to connect: UpcKeyGen.ps1 -ssid UPC1234567 -connect true
 #>
 param (
    [Parameter(Mandatory=$true)][string]$ssid,
    [Parameter(Mandatory=$false)][boolean]$connect=$false
 )
 
$path = Split-Path -parent $PSCommandPath
$upsSource = Get-Content (Join-Path $path "UpcKeyGen.cs") -Raw
$profileSource = Get-Content (Join-Path $path "profile.xml") -Raw
$tmpProfile = (Join-Path $path "tmp_profile.xml")
Add-Type -TypeDefinition $upsSource -Language CSharp
try {
  # generate both 2.4 and 5 GHz mode passwords
  Write-Host "Generating passwords for ssid $ssid" -ForegroundColor Cyan
  $candidates = ([Upc.UpcKeyGen]::GetCandidates($ssid, [Upc.Mode]::G24) + 
    [Upc.UpcKeyGen]::GetCandidates($ssid, [Upc.Mode]::G5))
} catch {
  Write-Host "An error during password generation" -ForegroundColor Red
  Write-Host $_.Exception.Message -ForegroundColor Red
  exit
}

ForEach ($candidate In $candidates) {
  $password = $candidate.Item2
  If ($connect) { 
    # create a wlan profile, import it and try connect
    [string]::Format($profileSource, $ssid, $password) | Set-Content -Path $tmpProfile
    netsh wlan delete profile name=$ssid
    netsh wlan add profile filename=$tmpProfile user=all
    netsh wlan connect name=$ssid
    If ($lastExitCode -eq 0) {
      Write-Host "Connected to ssid $ssid with password $password" -ForegroundColor Green
      Remove-Item $tmpProfile
      break
    } Else {
      Write-Host "Could not connected to ssid $ssid with password $password" -ForegroundColor Red
	  Remove-Item $tmpProfile
    }
  } Else {
    # just write the passord   
    Write-Host $password
  }
}
