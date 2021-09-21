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
        $tempUri = [Uri]::New($Obj.ToString())
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
                    $table[$prop] = $this.$prop.ToString("o")
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
                $this.$prop = [DateTime]::Parse($val)
                break
            }

            default {
                $this.$prop = $val
            }
        }
    }

    [int] DaysRemaining()
    {
        return [Math]::Round(($this.NotAfter - [DateTime]::Now).TotalDays, 2)
    }

    [int] DaysSinceLastAttempt()
    {
        return [Math]::Round(($this.LastAttempt - [DateTime]::Now).TotalDays, 2)
    }

    [int] DaysSinceLastConnect()
    {
        return [Math]::Round(($this.LastConnect - [DateTime]::Now).TotalDays, 2)
    }

    [bool] IsDateValid()
    {
        if ([DateTime]::Now -lt $this.NotBefore -or [DateTime]::Now -gt $this.NotAfter)
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
}

<#
#>
Function Get-EndpointCertificate
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
        $beginTime = [DateTime]::Now

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

            # Every certificate is valid for this check
            $certValidation = { $true }

            # Script to retrieve certificate extensions
            Function Get-CertificateExtension
            {
                [CmdletBinding()]
                param(
                    [Parameter(Mandatory=$true)]
                    [ValidateNotNullOrEmpty()]
                    [string]$KeyName,

                    [Parameter(Mandatory=$true)]
                    [ValidateNotNull()]
                    [HashTable]$Extensions
                )

                process
                {
                    $content = [string]::Empty

                    if ($Extensions.Keys -contains $KeyName)
                    {
                        $val = $Extensions[$KeyName]
                        if ($null -ne $val)
                        {
                            $content = $val.ToString()
                        }
                    }

                    $content
                }
            }

            # Build status object
            $status = @{
                Uri = $Uri
                LastAttempt = [DateTime]::Now
                Connected = $false
                LocallyTrusted = $false
            }

            $client = $null
            $stream = $null
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

                $stream = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false, $certValidation

                # This supplies the SNI to the endpoint
                Write-Verbose ("{0}: Sending SNI as {1}" -f $Uri, $Uri.Host)
                $stream.AuthenticateAsClient($Uri.Host)

                # Capture the remote certificate from the stream
                Write-Verbose ("{0}: Retrieving remote certificate" -f $Uri)
                $streamCert = $stream.RemoteCertificate
                $cert = New-Object 'System.Security.Cryptography.X509Certificates.X509Certificate2' -ArgumentList $streamCert

                # Convert the extensions to friendly names with data
                Write-Verbose ("{0}: Unpacking certificate extensions" -f $Uri)
                $extensions = @{}
                $cert.Extensions | ForEach-Object {
                    # Extract name. Use Oid if no friendly name
                    $name = $_.Oid.Value
                    if (![string]::IsNullOrEmpty($_.Oid.FriendlyName))
                    {
                        $name = $_.Oid.FriendlyName
                    }

                    $asndata = New-Object 'System.Security.Cryptography.AsnEncodedData' -ArgumentList $_.Oid, $_.RawData
                    $extensions[$name] = $asndata.Format($false)
                }

                # Pack the extensions in to a string object
                $extensionStr = $extensions.Keys | ForEach-Object {
                    $val = $extensions[$_]
                    if ([string]::IsNullOrEmpty($val))
                    {
                        $val = [string]::Empty
                    }
                    ("{0} = {1}" -f $_, $val)
                } | Join-String -Separator ([Environment]::Newline)

                # Get addresses for this endpoint
                $addresses = [System.Net.DNS]::GetHostAddresses($Uri.Host)

                # Update the hashtable with the entries we want to update on the CertificateInfo object
                Write-Verbose ("{0}: Updating object" -f $Uri)
                $status["Connected"] = $true
                $status["LastConnect"] = [DateTime]::Now
                $status["Subject"] = $cert.Subject
                $status["Issuer"] = $cert.Issuer
                $status["NotBefore"] = $cert.NotBefore
                $status["NotAfter"] = $cert.NotAfter
                $status["Thumbprint"] = $cert.Thumbprint
                $status["LocallyTrusted"] = $cert.Verify()
                $status["Extensions"] = $extensionStr
                $status["SAN"] = Get-CertificateExtension -KeyName "X509v3 Subject Alternative Name" -Extensions $extensions
                $status["EKU"] = Get-CertificateExtension -KeyName "X509v3 Extended Key Usage" -Extensions $extensions
                $status["BasicConstraints"] = Get-CertificateExtension -KeyName "X509v3 Basic Constraints" -Extensions $extensions
                $status["Addresses"] = $addresses | ForEach-Object { $_.ToString()} | Join-String -Separator ", "
            } catch {
                Write-Warning ("{0}: Failed to check endpoint: {1}" -f $Uri, $_)
                $status["LastErrorMsg"] = [string]$_
                $status["LastError"] = [DateTime]::Now
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

        Write-Verbose ("Total runtime: {0} seconds" -f ([DateTime]::Now - $beginTime).TotalSeconds)
    }
}

<#
#>
Function Write-ReportSection
{
    [CmdletBinding()]
    [OutputType([string], [System.Management.Automation.PSObject[]])]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [bool]$AsHtml,

        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSObject[]]$Content,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$Title,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$Description
    )

    process
    {
        # Write title and description information
        if ($AsHtml)
        {
            ("<b>{0}</b><br>" -f $Title)
            ("<i>{0}</i><br><p>" -f $Description)
            if ($null -ne $Content -and ($Content | Measure-Object).Count -gt 0)
            {
                $Content | ConvertTo-Html -As Table -Fragment
            } else {
                "No Content<br>"
            }
            "<br>"
        } else {
            Write-Information $Title
            Write-Information "================"
            Write-Information $Description
            Write-Information ""
            $Content
            Write-Information ""
        }
    }
}

<#
#>
Function Format-EndpointCertificateReport
{
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        [CertificateInfo]$CertificateInfo,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$AgeThresholdDays = 5,

        [Parameter(Mandatory=$false)]
        [switch]$AsHTML = $false
    )

    begin
    {
        # The function will accumulate the objects in to a list to report on
        # in 'end'
        $info = New-Object 'System.Collections.Generic.List[CertificateInfo]'
    }

    process
    {
        # Add the object to the list to report on once all objects have een received
        $info.Add($CertificateInfo) | Out-Null
    }

    end
    {
        $AgeThresholdDays = [Math]::Abs($AgeThresholdDays)

        if ($AsHTML)
        {
            "<!DOCTYPE html PUBLIC `"-//W3C//DTD XHTML 1.0 Strict//EN`"  `"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd`">"
            "<html xmlns=`"http://www.w3.org/1999/xhtml`">"
            "<head>"
            "<title>HTML TABLE</title>"
            "</head><body>"
        }

        # Display endpoints that couldn't be contacted
        $results = $info | Where-Object {$_.Connected -eq $false -or $_.LastConnect -lt ([DateTime]::Now.AddDays(-$AgeThresholdDays))} |
            Select-Object -Property Uri,Perspective,Subject,LastAttempt,LastConnect,Connected,LastError,LastErrorMsg
        Write-ReportSection -Content $results -AsHtml $AsHtml -Title "Inaccessible endpoints" -Description "Endpoints not connected within last $AgeThresholdDays days or failed connection"

        # get all endpoint data where the endpoint could be queried
        $connected = $info | Where-Object {$_.Connected}

        $results = $connected | Where-Object {$_.LocallyTrusted -eq $false -or $_.IsDateValid() -eq $false} |
        Select-Object -Property Uri,Perspective,Subject,Issuer,@{N="DaysRemaining";E={$_.DaysRemaining()}},LocallyTrusted
        Write-ReportSection -Content $results -AsHtml $AsHtml -Title "Invalid certificates" -Description "Endpoints with an invalid certificate (untrusted or date out of range)"

        $results = $connected | Where-Object {$_.NotAfter -lt ([DateTime]::Now.AddDays(90))} |
            Select-Object -Property Uri,Perspective,Subject,Issuer,@{N="DaysRemaining";E={$_.DaysRemaining()}},NotAfter,LocallyTrusted |
            Sort-Object -Property NotAfter
        Write-ReportSection -Content $results -AsHtml $AsHtml -Title "Endpoints expiring soon" -Description "All endpoints expiring within 90 days (Locally trusted or not)"

        if ($AsHTML)
        {
            "</body></html>"
        }
    }
}

<#
#>
Function Get-EndpointsFromAzureTableStorage
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
Function Update-EndpointsInAzureTableStorage
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
