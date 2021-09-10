<#
#>

########
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

<#
#>
Function Get-EndpointCertificate
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [Uri]$Uri,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Int]$ConcurrentChecks = 30,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Int]$TimeoutSec = 10
    )

    begin
    {
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
        $state = [PSCustomObject]@{
            runspaces = New-Object System.Collections.Generic.List[PSCustomObject]
        }

        # Common wait block to use in process and end
        # $target is the is the high count before we can schedule more checks
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
                        $result = $runspace.Runspace.EndInvoke($runspace.Status)

                        # Pass $result on in the pipeline
                        $result
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

            # Global settings
            $InformationPreference = "Continue"
            $ErrorActionPreference = "Stop"
            Set-StrictMode -Version 2

            # Every certificate is valid for this check
            $certValidation = { $true }

            $startTime = [DateTime]::Now
            $status = @{
                Uri = $Uri.ToString()
                Connected = $false
                CheckTime = $null
                Subject = $null
                Issuer = $null
                NotBefore = $null
                NotAfter = $null
                DaysRemaining = $null
                Thumbprint = $null
                DateValid = $null
                LocalVerify = $null
                Extensions = $null
                SAN = $null
                Raw = $null
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

                # Extract the SAN, if it is present
                Write-Verbose ("{0}: checking for SAN extension" -f $Uri)
                $san = [string]::Empty
                $sanKey = "X509v3 Subject Alternative Name"
                if ($extensions.Keys -contains $sanKey)
                {
                    $san = $extensions[$sanKey]
                }

                # Generate an ease of use object, with original cert data
                Write-Verbose ("{0}: Updating object" -f $Uri)
                $status["Connected"] = $true
                $status["Subject"] = $cert.Subject
                $status["Issuer"] = $cert.Issuer
                $status["NotBefore"] = $cert.NotBefore
                $status["NotAfter"] = $cert.NotAfter
                $status["DaysRemaining"] = [Math]::Round((($cert.NotAfter - [DateTime]::Now).TotalDays), 2)
                $status["Thumbprint"] = $cert.Thumbprint
                $status["DateValid"] = ($cert.NotAfter -gt [DateTime]::Now -and $cert.NotBefore -lt [DateTime]::Now)
                $status["LocalVerify"] = $cert.Verify()
                $status["Extensions"] = $extensions
                $status["SAN"] = $san
                $status["Raw"] = $cert
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
            $status["CheckTime"] = (([DateTime]::Now - $startTime).TotalSeconds)
            [PSCustomObject]$status
        }
    }

    process
    {
        # Wait for runspace level to go under ConcurrentChecks
        Invoke-Command -Script $waitScript -ArgumentList $state, ($ConcurrentChecks-1)

        # Schedule a run for this uri
        Write-Verbose ("{0}: Scheduling check" -f $Uri)
        $runspace = [PowerShell]::Create()
        $runspace.AddScript($checkScript) | Out-Null
        $runspace.AddParameter("Uri", $Uri) | Out-Null
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
        [PSCustomObject]$CertificateInfo
    )

    begin
    {
        $info = New-Object 'System.Collections.Generic.List[PSCustomObject]'
    }

    process
    {
        $info.Add($CertificateInfo) | Out-Null
    }

    end
    {
        Write-Information "Endpoints that failed checking"
        Write-Information "================"
        Write-Information ""
        ($info | Where-Object {$_.Connected -eq $false}).Uri

        Write-Information "Endpoints with an invalid certificate (failed validation or date out of range)"
        Write-Information "================"
        Write-Information ""
        $info | Where-Object {$_.LocalVerify -eq $false -or $_.DateValid -eq $false} | Format-Table -Property Uri,Subject,Issuer,DaysRemaining,LocalVerify

        $valid = $info | Where-Object {$_.LocalVerify -eq $true -and $_.DateValid -eq $true}
        Write-Information "Valid endpoints expiring within 90 days"
        Write-Information "================"
        Write-Information ""
        $valid | Where-Object {$_.NotAfter -lt ([DateTime]::Now.AddDays(90))} | Sort-Object -Property DaysRemaining | Format-Table -Property Uri,Subject,Issuer,DaysRemaining,NotAfter

        Write-Information "All other valid endpoints"
        Write-Information "================"
        Write-Information ""
        $valid | Where-Object {$_.NotAfter -ge ([DateTime]::Now.AddDays(90))} | Sort-Object -Property DaysRemaining | Format-Table -Property Uri,Subject,Issuer,DaysRemaining,NotAfter
    }
}