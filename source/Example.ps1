
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

Remove-Module CertCheck -EA Ignore
Import-Module ./CertCheck/CertCheck.psm1

@([PSCustomObject]@{
    Connection = "https://www.google.com.au"
    Sni = "elsewhere.local"
}, @{
    Connection = "https://www.microsoft.com"
    Sni = "tester.microsoft.com"
}, "https://www.news.com.au",
[Uri]"https://toggl.com",
"https://toggl.com",
"https://www.news.com.au") | Test-EndpointCertificate | Format-Table Connection, Sni, Subject

Test-EndpointCertificate -Connection "https://www.google.com.au" | Format-Table Connection, Sni, Subject
"https://www.google.com.au" | Test-EndpointCertificate | Format-Table Connection, Sni, Subject
"https://www.google.com.au" | Test-EndpointCertificate -Sni test | Format-Table Connection, Sni, Subject
Test-EndpointCertificate -Connection "https://www.google.com.au" -Sni test | Format-Table Connection, Sni, Subject
