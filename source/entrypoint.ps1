[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNull()]
    [Uri]$Endpoint
)

# Global settings
Set-StrictMode -Version 2
$InformationPreference = "Continue"
$ErrorActionPreference = "Continue"

Import-Module CertCheck

Test-EndpointCertificate -Endpoint $Endpoint
