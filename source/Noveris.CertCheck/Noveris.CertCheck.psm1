<#
#>

########
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

# Import Azure functions, but don't fail if we cant
# All Azure Tables code should be in a separate module, but is here for the moment
# Not requiring AzTable allows the module to be imported for systems that
# wont use Azure functionality and don't have AzTable installed
Import-Module AzTable -EA SilentlyContinue

<#
#>
Function New-NormalisedUri
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([System.Uri])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $Obj
    )

    process
    {
        $tempUri = [Uri]::New($Obj.ToString().ToLower())
        $uri = [Uri]::New(("{0}://{1}:{2}" -f $tempUri.Scheme, $tempUri.Host, $tempUri.Port))

        $uri
    }
}

Class CertificateInfo
{
    CertificateInfo()
    {
    }

    CertificateInfo([string] $uri)
    {
        $this.Uri = New-NormalisedUri $uri
    }

    CertificateInfo([Uri] $uri)
    {
        $this.Uri = New-NormalisedUri $uri
    }

    CertificateInfo([HashTable] $table)
    {
        $this.UpdateFromHashTable($table)
    }

    CertificateInfo([PSObject] $obj)
    {
        $this.UpdateFromObject($obj)
    }

    [HashTable] ToHashTable()
    {
        $table = @{}

        ($this | Get-Member | Where-Object {$_.MemberType -eq "Property"}).Name | ForEach-Object {
            $prop = $_

            switch ($this.$prop.GetType().FullName)
            {
                "System.DateTime" {
                    $table[$prop] = $this.$prop.ToUniversalTime().ToString("o")
                    break
                }

                default {
                    $table[$prop] = [string]($this.$prop)
                    break
                }
            }
        }

        return $table
    }

    [void] UpdateFromObject([PSObject] $obj)
    {
        ($obj | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty" -or $_.MemberType -eq "Property"}).Name | ForEach-Object {
            if (($this | Get-Member | Where-Object {$_.MemberType -eq "Property"}).Name -contains $_)
            {
                $this.UpdatePropertyFromString($_, $obj.$_.ToString())
            }
        }
    }

    [void] UpdateFromHashTable([HashTable] $table)
    {
        $table.Keys | ForEach-Object {
            if (($this | Get-Member | Where-Object {$_.MemberType -eq "Property"}).Name -contains $_)
            {
                $this.UpdatePropertyFromString($_, $table[$_].ToString())
            }
        }
    }

    [void] UpdatePropertyFromString([string] $prop, [string] $val)
    {
        switch ($this.$prop.GetType().FullName)
        {
            "System.Uri" {
                $this.$prop = New-NormalisedUri $val
                break
            }

            "System.Boolean" {
                $this.$prop = [bool]::Parse($val)
                break
            }

            "System.DateTime" {
                $this.$prop = [DateTime]::Parse($val).ToUniversalTime()
                break
            }

            default {
                $this.$prop = $val
            }
        }
    }

    [int] DaysRemaining()
    {
        return [Math]::Round(($this.NotAfter - [DateTime]::UtcNow).TotalDays, 2)
    }

    [int] DaysSinceLastAttempt()
    {
        return [Math]::Round(($this.LastAttempt - [DateTime]::UtcNow).TotalDays, 2)
    }

    [int] DaysSinceLastConnect()
    {
        return [Math]::Round(($this.LastConnect - [DateTime]::UtcNow).TotalDays, 2)
    }

    [bool] IsDateValid()
    {
        if ([DateTime]::UtcNow -lt $this.NotBefore.ToUniversalTime() -or [DateTime]::UtcNow -gt $this.NotAfter.ToUniversalTime())
        {
            return $false
        }

        return $true
    }

    [Uri]$Uri = [string]::Empty
    [bool]$Connected = $false
    [DateTime]$LastAttempt
    [DateTime]$LastConnect

    [string]$Perspective = [string]::Empty
    [string]$Subject = [string]::Empty
    [string]$Issuer = [string]::Empty
    [DateTime]$NotBefore
    [DateTime]$NotAfter
    [string]$Thumbprint = [string]::Empty
    [bool]$LocallyTrusted = $false
    [string]$SAN = [string]::Empty
    [string]$EKU = [string]::Empty
    [string]$BasicConstraints = [string]::Empty
    [string]$Extensions = [string]::Empty
    [DateTime]$LastError
    [string]$LastErrorMsg = [string]::Empty
    [string]$Addresses = [string]::Empty
    [string]$CertPath = [string]::Empty
}

<#
#>
Function New-CertificateInfo
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,ValueFromPipeline)]
        [ValidateNotNull()]
        $Obj
    )

    process
    {
        if ($PSBoundParameters.Keys -contains "Obj")
        {
            [CertificateInfo]::New($Obj)
        } else {
            [CertificateInfo]::New()
        }
    }
}

<#
#>
Function Test-EndpointCertificate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        [CertificateInfo]$Endpoint,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Int]$ConcurrentChecks = 30,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Int]$TimeoutSec = 10
    )

    begin
    {
        # We'll verbose report on the total run time later on
        $beginTime = [DateTime]::UtcNow

        # Create runspace environment
        Write-Verbose "Creating runspace pool"
        $pool = [RunSpaceFactory]::CreateRunspacePool(1, $ConcurrentChecks)
        if (($pool | Get-Member).Name -contains "ApartmentState")
        {
            $pool.ApartmentState = "MTA"
        }

        $pool.Open()

        # Use a custom object so the wait block can replace the list with a new list
        # (i.e. update the reference)
        $state = [PSCustomObject]@{
            runspaces = New-Object System.Collections.Generic.List[PSCustomObject]
        }

        # Common wait block to use to process finished runspaces
        # $target is the is the high count before we can schedule more checks
        # script returns a hashtable of properties to update on the CertificateInfo object
        $waitScript = {
            param($state, $target)

            while (($state.runspaces | Measure-Object).Count -gt $target)
            {
                # Separate tasks in to completed and not
                $tempList = New-Object System.Collections.Generic.List[PSCustomObject]
                $completeList = New-Object System.Collections.Generic.List[PSCustomObject]
                $state.runspaces | ForEach-Object {
                    if ($_.Status.IsCompleted)
                    {
                        $completeList.Add($_)
                    } else {
                        $tempList.Add($_)
                    }
                }
                $state.runspaces = $tempList

                # Process completed runspaces
                $completeList | ForEach-Object {
                    $runspace = $_

                    try {
                        $result = $runspace.Runspace.EndInvoke($runspace.Status) | Select-Object -First 1

                        # Build and pass CertificateInfo on in the pipeline
                        [CertificateInfo]::New($result)
                    } catch {
                        Write-Warning "Error reading return from runspace job: $_"
                        Write-Warning ($_ | Format-List -property * | Out-String)
                    }

                    $runspace.Runspace.Dispose()
                    $runspace.Status = $null
                }

                Start-Sleep -Seconds 1
            }
        }

        # Script for checking certificates on endpoint
        $checkScript = {
            param(
                [Parameter(Mandatory=$true)]
                [ValidateNotNull()]
                [Uri]$Uri,

                [Parameter(Mandatory=$false)]
                [ValidateNotNull()]
                [Int]$TimeoutSec = 10
            )

            # Note - The check script runs in a runspace, so doesn't have implicit access
            # to all of the types in the parent powershell scope. This script doesn't have
            # access to the CertificateInfo type.

            # Global settings
            $InformationPreference = "Continue"
            $ErrorActionPreference = "Stop"
            Set-StrictMode -Version 2

            # Script to retrieve certificate extensions
            Function Get-CertificateExtension
            {
                [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
                [OutputType('System.String')]
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNullOrEmpty()]
                    [string]$Oid,

                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                    [PSCustomObject[]]$Extensions
                )

                process
                {
                    $content = $Extensions |
                        Where-Object { $_.Oid -eq $Oid } |
                        Select-Object -First 1 |
                        ForEach-Object { $_.Value }

                    if ([string]::IsNullOrEmpty($content))
                    {
                        [string]::Empty
                    } else {
                        $content
                    }
                }
            }

            Function Get-CertificateData
            {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                    [Uri]$Uri,

                    [Parameter(Mandatory=$false)]
                    [ValidateNotNull()]
                    [switch]$NoValidation,

                    [Parameter(Mandatory=$false)]
                    [ValidateNotNull()]
                    [Int]$TimeoutSec = 10
                )

                process
                {
                    # 'No Validation' callback
                    $certValidation = { $true }

                    # stream and client for disposal later
                    $client = $null
                    $stream = $null

                    # Status object to report on connection, auth and cert
                    $status = [PSCustomObject]@{
                        AuthSuccess = $false
                        Connected = $false
                        Certificate = $null
                        Error = [string]::Empty
                    }

                    try {
                        # Construct TcpClient and stream to target
                        Write-Verbose ("{0}: Connecting" -f $Uri)
                        $client = New-Object System.Net.Sockets.TcpClient

                        # Tasks for connect and timeout
                        $connect = $client.ConnectAsync($Uri.Host, $Uri.Port)
                        $connect.Wait($TimeoutSec * 1000) | Out-Null

                        # Check if we timed out
                        if (!$connect.IsCompleted)
                        {
                            # Connect didn't finish in time
                            Write-Error ("{0}: Failed to connect" -f $Uri)
                        }

                        # Update status
                        $status.Connected = $true

                        # Configure the SslStream connection
                        $stream = $null
                        if ($NoValidation)
                        {
                            $stream = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false, $certValidation
                        } else {
                            $stream = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false
                        }

                        # This supplies the SNI to the endpoint
                        Write-Verbose ("{0}: Sending SNI as {1}" -f $Uri, $Uri.Host)
                        $stream.AuthenticateAsClient($Uri.Host)

                        # Update status
                        $status.AuthSuccess = $true

                        # Capture the remote certificate from the stream
                        Write-Verbose ("{0}: Retrieving remote certificate" -f $Uri)
                        $streamCert = $stream.RemoteCertificate
                        $status.Certificate = New-Object 'System.Security.Cryptography.X509Certificates.X509Certificate2' -ArgumentList $streamCert
                    } catch {
                        $status.Error = $_.ToString()
                    } finally {
                        if ($null -ne $stream)
                        {
                            $stream.Dispose()
                        }

                        if ($null -ne $client)
                        {
                            $client.Dispose()
                        }
                    }

                    # Return status object
                    $status
                }
            }

            # Build status object
            $status = @{
                Uri = $Uri
                LastAttempt = [DateTime]::UtcNow
                Connected = $false
            }

            try {
                # Get-CertificateData doesn't throw errors, just returns the status object
                # Attempt to connect with certificate validation on first attempt
                $connectStatus = Get-CertificateData -Uri $Uri -TimeoutSec $TimeoutSec

                # If we can't connect, just stop here
                if (!$connectStatus.Connected)
                {
                    Write-Verbose "Coult not connect to endpoint"
                    Write-Error $connectStatus.Error
                }

                $failedAuth = $false
                if (!$connectStatus.AuthSuccess -or $null -eq $connectStatus.Certificate)
                {
                    # We connected, but failed authentication or didn't receive a certificate
                    # Attempt to reconnect, but without validation of certificates
                    Write-Verbose "Validation of remote endpoint failed. Reattempting without validation."
                    $connectStatus = Get-CertificateData -Uri $Uri -TimeoutSec $TimeoutSec -NoValidation
                    $failedAuth = $true
                }

                if (!$connectStatus.AuthSuccess -or !$connectStatus.Connected -or $null -eq $connectStatus.Certificate)
                {
                    # Issue with connecting to the endpoint here. Can't continue
                    Write-Verbose "Endpoint connectivity or auth failure"
                    Write-Error $connectStatus.Error
                }

                $cert = $connectStatus.Certificate

                # Convert the extensions to friendly names with data
                Write-Verbose ("{0}: Unpacking certificate extensions" -f $Uri)
                $extensions = $cert.Extensions | ForEach-Object {
                    $asndata = New-Object 'System.Security.Cryptography.AsnEncodedData' -ArgumentList $_.Oid, $_.RawData

                    $friendlyName = [string]::Empty
                    if (!([string]::IsNullOrEmpty($_.Oid.FriendlyName)))
                    {
                        $friendlyName = $_.Oid.FriendlyName
                    }

                    [PSCustomObject]@{
                        Oid = $_.Oid.Value
                        FriendlyName = $friendlyName
                        Value = $asndata.Format($false)
                    }
                }

                # Pack the extensions in to a string object
                $extensionStr = ($extensions | ForEach-Object {
                    ("{0}({1}) = {2}{3}" -f $_.FriendlyName, $_.Oid, $_.Value, [Environment]::NewLine)
                } | Out-String).TrimEnd([Environment]::NewLine)

                # Get addresses for this endpoint
                $addresses = [System.Net.DNS]::GetHostAddresses($Uri.Host)

                # Build chain information for this certificate
                $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::New()
                $chain.Build($cert) | Out-Null
                $certPath = ($chain.ChainElements |
                    ForEach-Object { $_.Certificate.Subject.ToString() + [Environment]::NewLine } |
                    Out-String).TrimEnd([Environment]::NewLine)

                # Update the hashtable with the entries we want to update on the CertificateInfo object
                Write-Verbose ("{0}: Updating object" -f $Uri)
                $status["Connected"] = $true
                $status["LastConnect"] = [DateTime]::UtcNow
                $status["Subject"] = $cert.Subject
                $status["Issuer"] = $cert.Issuer
                $status["NotBefore"] = $cert.NotBefore.ToUniversalTime()
                $status["NotAfter"] = $cert.NotAfter.ToUniversalTime()
                $status["Thumbprint"] = $cert.Thumbprint
                $status["LocallyTrusted"] = !$failedAuth
                $status["Extensions"] = $extensionStr
                $status["SAN"] = Get-CertificateExtension -Oid "2.5.29.17" -Extensions $extensions
                $status["EKU"] = Get-CertificateExtension -Oid "2.5.29.37" -Extensions $extensions
                $status["BasicConstraints"] = Get-CertificateExtension -Oid "2.5.29.19" -Extensions $extensions
                $status["Addresses"] = ($addresses | ForEach-Object { $_.ToString() + [Environment]::NewLine } | Out-String).TrimEnd([Environment]::NewLine)
                $status["CertPath"] = $certPath
            } catch {
                Write-Warning ("{0}: Failed to check endpoint: {1}" -f $Uri, $_)
                $status["LastErrorMsg"] = [string]$_
                $status["LastError"] = [DateTime]::UtcNow
            }

            # Return the state object
            $status
        }
    }

    process
    {
        # Wait for runspace level to go under ConcurrentChecks
        Invoke-Command -Script $waitScript -ArgumentList $state, ($ConcurrentChecks-1)

        # Schedule a run for this uri
        Write-Verbose ("{0}: Scheduling check" -f $Endpoint.Uri)
        $runspace = [PowerShell]::Create()
        $runspace.AddScript($checkScript) | Out-Null
        $runspace.AddParameter("Uri", $Endpoint.Uri) | Out-Null
        $runspace.AddParameter("TimeoutSec", $TimeoutSec) | Out-Null
        $runspace.RunspacePool = $pool

        $state.runspaces.Add([PSCustomObject]@{
            Runspace = $runspace
            Status = $runspace.BeginInvoke()
        })
    }

    end
    {
        # Wait for all runspaces to finish
        Write-Verbose "Waiting for remainder of runspaces to finish"
        Invoke-Command -Script $waitScript -ArgumentList $state, 0

        # Close everything off
        $pool.Close()
        $pool.Dispose()

        Write-Verbose ("Total runtime: {0} seconds" -f ([DateTime]::UtcNow - $beginTime).TotalSeconds)
    }
}

<#
#>
Function Get-EndpointCertificate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$Table,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Perspective
    )

    process
    {
        # Args for Get-AzTableRow
        $getArgs = @{
            Table = $Table
        }

        # Refine to a perspective, if requested
        if (![string]::IsNullOrEmpty($Perspective))
        {
            $getArgs["PartitionKey"] = $Perspective
        }

        # Get all rows, perhaps filtering to a perspective/partitionkey
        Get-AzTableRow @getArgs | ForEach-Object {
            $row = $_

            # Extract properties from the row and populate the status object
            $info = [CertificateInfo]::New($row)
            $info.Perspective = $row.PartitionKey

            # Check Uri
            try {
                # Extract the Uri from the RowKey
                $bytes = [Convert]::FromBase64String($row.RowKey)
                $uri = [System.Text.Encoding]::Unicode.GetString($bytes)

                $testUri = [Uri]::New($uri)

                if ([string]::IsNullOrEmpty($testUri.Host) -or $testUri.Port -eq 0)
                {
                    Write-Warning "Missing host and/or port in Uri: $uri"
                } else {
                    $info.Uri = $testUri
                    $info
                }
            } catch {
                Write-Warning ("Invalid format for uri. Raw RowKey({0})" -f $row.RowKey)
            }
        }
    }
}

<#
#>
Function Add-EndpointCertificate
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$Table,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Perspective,

        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        [CertificateInfo]$Update
    )

    process
    {
        $uri = $Update.Uri
        # Check for host and port
        if ([string]::IsNullOrEmpty($uri.Host) -or $uri.Port -eq 0)
        {
            Write-Error "Missing host and/or port in Uri"
        }

        $status = $Update.ToHashTable()

        # Determine PartitionKey
        # Use the supplied Perspective. If empty, use the Perspective in the CertificateInfo
        $partitionKey = $Perspective
        if ([string]::IsNullOrEmpty($partitionKey) -and $status.Keys -contains "Perspective")
        {
            $partitionKey = $status["Perspective"]
        }

        # No supplied Perspective and no Perspective in the CertificateInfo object, so use "global"
        if ([string]::IsNullOrEmpty($partitionKey))
        {
            $partitionKey = "global"
        }

        # Write it back to the status object so that the content in Azure Tables is consistent
        $status["Perspective"] = $partitionKey

        # Rewrite/transform uri to base64 encoding
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($uri)
        $rowKey = [Convert]::ToBase64String($bytes)

        # Add/Update the row
        Write-Verbose "Updating Partition($Perspective) RowKey($rowKey)"
        Write-Verbose "Properties: "
        Write-Verbose ([PSCustomObject]$status | ConvertTo-Json)
        Add-AzTableRow -Table $table -PartitionKey $partitionKey -RowKey $rowKey -Property $status -UpdateExisting | Out-Null
    }
}


<#
#>
Function Merge-EndpointCategory
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$CategoryTable,

        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [AllowNull()]
        [CertificateInfo]$Info
    )

    begin
    {
        # Get all category/uri pairs
        Write-Verbose "Collecting category information from table"
        $categoryMap = Get-CategoryUri -Table $CategoryTable |
            Group-Object -Property Uri -AsHashTable
        if ($null -eq $categoryMap -or ($categoryMap | Measure-Object).Count -eq 0)
        {
            Write-Warning "No category information found"
        } else {
            Write-Verbose ("Found {0} items in category map" -f ($categoryMap.Keys | Measure-Object).Count)
        }
    }

    process
    {
        if ($null -ne $Info)
        {
            # Add category information to endpoints
            $Info | Add-Member -NotePropertyName Categories -NotePropertyValue "" -Force

            $uri = $Info.Uri.ToString()
            if ($null -ne $categoryMap -and $categoryMap.Keys -contains $uri -and ($categoryMap[$uri] | Measure-Object).Count -gt 0)
            {
                $Info.Categories = $categoryMap[$uri] | ForEach-Object { $_.CategoryName } | Join-String -Separator ", "
            }
        }
    }
}

<#
#>
Function Add-CategoryUri
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$Table,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$CategoryName,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Uri]$Uri
    )

    process
    {
        # Normalise Uri for processing
        $Uri = New-NormalisedUri $Uri

        # only lowercase for category names
        $CategoryName = $CategoryName.ToLower()

        # Generate Base64 representations
        $rowKey = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Uri))
        $partitionKey = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($CategoryName))

        # Data for the entry
        $entry = @{}

        # Add/Update the row
        Write-Verbose "Updating Partition($partitionKey) RowKey($rowKey)"
        Write-Verbose "Properties: "
        Write-Verbose ([PSCustomObject]$entry | ConvertTo-Json)
        Add-AzTableRow -Table $table -PartitionKey $partitionKey -RowKey $rowKey -Property $entry -UpdateExisting | Out-Null
    }
}

Function Get-CategoryUri
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$Table,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$CategoryName,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Uri]$Uri
    )

    process
    {
        # Base for parameters for the request
        $getParams = @{
            Table = $Table
        }

        # Set the partition key to the category name, if supplied
        if ($PSBoundParameters.Keys -contains "CategoryName")
        {
            # only lowercase for category names
            $CategoryName = $CategoryName.ToLower()

            $getParams["PartitionKey"] = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($CategoryName))
        }

        # Set the row key to the Uri, if supplied
        if ($PSBoundParameters.Keys -contains "Uri")
        {
            # Normalise Uri for processing
            $Uri = New-NormalisedUri $Uri
            $getParams["RowKey"] = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Uri))
        }

        # Retrieve the rows and convert to native category name and uri
        Get-AzTableRow @getParams | ForEach-Object {
            try {
                [PSCustomObject]@{
                    CategoryName = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($_.PartitionKey))
                    Uri = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($_.RowKey))
                }
            } catch {
                Write-Warning "Error retrieving/converting document: $_"
            }
        }
    }
}

Function Remove-CategoryUri
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$Table,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$CategoryName,

        [Parameter(Mandatory=$true,ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Uri]$Uri
    )

    process
    {
        # Normalise Uri for processing
        $Uri = New-NormalisedUri $Uri

        # only lowercase for category names
        $CategoryName = $CategoryName.ToLower()

        # Base for parameters for the request
        $removeParams = @{
            Table = $Table
            PartitionKey = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($CategoryName))
            RowKey = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Uri))
        }

        # Retrieve the rows and convert to native category name and uri
        try {
            Remove-AzTableRow @removeParams
        } catch {
            Write-Error "Error removing Azure Table row: $_"
        }
    }
}

<#
#>
Function Format-EndpointReport
{
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$AsHtml = $false,

        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [AllowNull()]
        $Obj,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Title = ""
    )

    begin
    {
        $objList = New-Object 'System.Collections.ArrayList'

        if ($AsHTML)
        {
            "<!DOCTYPE html PUBLIC `"-//W3C//DTD XHTML 1.0 Strict//EN`"  `"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd`">"
            "<html xmlns=`"http://www.w3.org/1999/xhtml`">"
            "<head>"
            "<title>$Title</title>"
            "<style>"
            "table {"
            "  font-family: Arial, Helvetica, sans-serif;"
            "  border-collapse: collapse;"
            "  width: 100%;"
            "}"
            "td, th {"
            "  border: 1px solid #ddd;"
            "  padding: 8px;"
            "}"
            "tr:nth-child(even){background-color: #f2f2f2;}"
            "tr:hover {background-color: #ddd;}"
            "th {"
            "  padding-top: 12px;"
            "  padding-bottom: 12px;"
            "  text-align: left;"
            "  background-color: #04AA6D;"
            "  color: white;"
            "}"
            "</style>"
            "</head><body>"
        }
    }

    process
    {
        if ($AsHtml)
        {
            $objList.Add($Obj) | Out-Null
        } else {
            $Obj
        }
    }

    end
    {
        if ($AsHTML)
        {
            $objList | Out-String
            "</body></html>"
        }
    }
}

<#
#>
Function Format-EndpointReportSection
{
    [CmdletBinding()]
    [OutputType([string], [System.Management.Automation.PSObject[]])]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$AsHtml,

        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [AllowNull()]
        [PSObject]$Content,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$Title,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$Description,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$RecoverHtmlTags = $true
    )

    begin
    {
        $objList = New-Object 'System.Collections.ArrayList'
    }

    process
    {
        $objList.Add($Content) | Out-Null
    }

    end
    {
        # Write title and description information
        if ($AsHtml)
        {
            ("<b>{0}</b><br>" -f $Title)
            ("<i>{0}</i><br><p>" -f $Description)
            if (($objList | Measure-Object).Count -gt 0)
            {
                $content = $objList |
                    ConvertTo-Html -As Table -Fragment |
                    Out-String

                # Decode any Html tags, if required
                if ($RecoverHtmlTags)
                {
                    $content = [System.Web.HttpUtility]::HtmlDecode($content)
                }

                # output the html result
                $content
            } else {
                "No Content<br />"
            }
            "<br>"
        } else {
            $Title
            "================"
            $Description
            ""
            $objList | Format-Table
            ""
        }
    }
}
