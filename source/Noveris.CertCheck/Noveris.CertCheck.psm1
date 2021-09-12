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

Class CertificateInfo
{
    CertificateInfo()
    {
    }

    CertificateInfo([string] $uri)
    {
        $this.Uri = [Uri]::New($uri)
    }

    CertificateInfo([Uri] $uri)
    {
        $this.Uri = [Uri]::New($uri)
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
            $table[$_] = [string]($this.$_)
        }

        return $table
    }

    [void] UpdateFromObject([PSObject] $obj)
    {
        ($obj | Get-Member | Where-Object {$_.MemberType -eq "NoteProperty" -or $_.MemberType -eq "Property"}).Name | ForEach-Object {
            if (($this | Get-Member | Where-Object {$_.MemberType -eq "Property"}).Name -contains $_)
            {
                $val = $null

                switch ($_)
                {
                    "Uri" {
                        $val = [Uri]::New($obj.$_.ToString())
                        break
                    }

                    "Connected" {
                        $val = [bool]::Parse($obj.$_.ToString())
                        break
                    }

                    "LocallyTrusted" {
                        $val = [bool]::Parse($obj.$_.ToString())
                        break
                    }

                    default {
                        $val = $obj.$_
                    }
                }

                $this.$_ = $val
            }
        }
    }

    [void] UpdateFromHashTable([HashTable] $table)
    {
        $table.Keys | ForEach-Object {
            if (($this | Get-Member | Where-Object {$_.MemberType -eq "Property"}).Name -contains $_)
            {
                $val = $null

                switch ($_)
                {
                    "Uri" {
                        $val = [Uri]::New($table[$_].ToString())
                        break
                    }

                    "Connected" {
                        $val = [bool]::Parse($table[$_].ToString())
                        break
                    }

                    "LocallyTrusted" {
                        $val = [bool]::Parse($table[$_].ToString())
                        break
                    }

                    default {
                        $val = $table[$_]
                    }
                }

                $this.$_ = $val
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

    [string]$Subject = [string]::Empty
    [string]$Issuer = [string]::Empty
    [DateTime]$NotBefore
    [DateTime]$NotAfter
    [string]$Thumbprint = [string]::Empty
    [bool]$LocallyTrusted = $false
    [string]$SAN = [string]::Empty
    [string]$Extensions = [string]::Empty
}

<#
#>
Function Get-EndpointCertificate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        [CertificateInfo]$CertInfo,

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

                $stream = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), false, $certValidation

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
                    $asndata = New-Object 'System.Security.Cryptography.AsnEncodedData' -ArgumentList $_.Oid, $_.RawData
                    $extensions[$asndata.Oid.FriendlyName] = $asndata.Format($false)
                }

                # Pack the extensions in to a string object
                $extensionStr = $extensions.Keys | ForEach-Object {
                    ("{0} = {1}" -f $_, $extensions[$_])
                } | Join-String -Separator ([Environment]::Newline)

                # Extract the SAN, if it is present
                Write-Verbose ("{0}: checking for SAN extension" -f $Uri)
                $san = [string]::Empty
                $sanKey = "X509v3 Subject Alternative Name"
                if ($extensions.Keys -contains $sanKey)
                {
                    $san = $extensions[$sanKey]
                }

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
                $status["SAN"] = $san
            } catch {
                Write-Information ("{0}: Failed to check endpoint: {1}" -f $Uri, $_)
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
        Write-Verbose ("{0}: Scheduling check" -f $CertInfo.Uri)
        $runspace = [PowerShell]::Create()
        $runspace.AddScript($checkScript) | Out-Null
        $runspace.AddParameter("Uri", $CertInfo.Uri) | Out-Null
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
Function Format-CertificateReport
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNull()]
        [CertificateInfo]$CertificateInfo
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
        Write-Information "Endpoints that failed checking"
        Write-Information "================"
        Write-Information ""
        ($info | Where-Object {$_.Connected -eq $false}).Uri | ForEach-Object { $_.ToString() }
        Write-Information ""

        Write-Information "Endpoints with an invalid certificate (failed validation or date out of range)"
        Write-Information "================"
        Write-Information ""
        $info | Where-Object {$_.Connected -eq $true -and ($_.LocallyTrusted -eq $false -or $_.IsDateValid() -eq $false)} |
            Format-List -Property Uri,Subject,Issuer,@{N="DaysRemaining";E={$_.DaysRemaining()}},LocallyTrusted
        Write-Information ""

        $valid = $info | Where-Object {$_.Connected -and ($_.LocallyTrusted -eq $true -and $_.IsDateValid() -eq $true)}
        Write-Information "Valid endpoints expiring within 90 days"
        Write-Information "================"
        Write-Information ""
        $valid | Where-Object {$_.NotAfter -lt ([DateTime]::Now.AddDays(90))} |
            Sort-Object -Property DaysRemaining |
            Format-List -Property Uri,Subject,Issuer,@{N="DaysRemaining";E={$_.DaysRemaining()}},NotAfter
        Write-Information ""

        Write-Information "All other valid endpoints"
        Write-Information "================"
        Write-Information ""
        $valid | Where-Object {$_.NotAfter -ge ([DateTime]::Now.AddDays(90))} |
            Sort-Object -Property DaysRemaining |
            Format-List -Property Uri,Subject,Issuer,@{N="DaysRemaining";E={$_.DaysRemaining()}},NotAfter
        Write-Information ""
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
        [string]$Partition = "primary"
    )

    process
    {
        # Retrieve all rows for this partition
        Get-AzTableRow -Table $Table -Partition $Partition | ForEach-Object {
            $row = $_

            # Extract properties from the row and populate the status object
            $info = [CertificateInfo]::New($row)

            # Extract the Uri from the RowKey
            $bytes = [Convert]::FromBase64String($row.RowKey)
            $uri = [System.Text.Encoding]::Unicode.GetString($bytes)

            # Check Uri
            try {
                $testUri = [Uri]::New($uri)

                if ([string]::IsNullOrEmpty($testUri.Host) -or $testUri.Port -eq 0)
                {
                    Write-Warning "Missing host and/or port in Uri: $uri"
                } else {
                    $info.Uri = $testUri
                    $info
                }
            } catch {
                Write-Warning "Invalid format for uri: $uri"
            }
        }
    }
}

<#
#>
Function Update-EndpointsInAzureTableStorage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$Table,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Partition = "primary",

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

        # Rewrite/transform uri to base64 encoding
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($uri)
        $rowKey = [Convert]::ToBase64String($bytes)

        # Add/Update the row
        Write-Verbose "Updating Partition($Partition) RowKey($rowKey)"
        Write-Verbose "Properties: "
        Write-Verbose ([PSCustomObject]$status | ConvertTo-Json)
        Add-AzTableRow -Table $table -PartitionKey $Partition -RowKey $rowKey -Property $status -UpdateExisting | Out-Null
    }
}
