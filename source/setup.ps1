
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

@("AzTable", "Az.Storage", "Az.Resources") | ForEach-Object {
    Install-Module $_ -AcceptLicense -Force -Scope AllUsers
}
