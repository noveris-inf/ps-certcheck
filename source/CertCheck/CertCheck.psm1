<#
#>

########
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

Add-Type @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class ServerCertificateValidationCallback
    {
        public static bool IgnoreCertificateValidation(Object obj,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors errors)
        {
            return true;
        }
    }
"@

<#
#>
Function New-NormalisedUri
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([System.Uri])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $UriObj,

        [Parameter(Mandatory=$false)]
        [switch]$AsString = $false
    )

    process
    {
        $uri = $UriObj

        # Check for string without scheme prefix
        if ($uri.GetType().FullName -eq "System.String" -and $uri -notmatch "://")
        {
            # Is a string, but doesn't appear to have a scheme prefix
            $uri = "https://" + $uri
        }

        # If it's not a URI, attempt to convert to Uri directly
        if ($uri.GetType().FullName -ne "System.Uri")
        {
            try {
                $uri = [Uri]::New($uri)
            } catch {
                # Could not convert to Uri directly
            }
        }

        # If it's still not a URI, attempt to convert to Uri with a https:// prefix
        if ($uri.GetType().FullName -ne "System.Uri")
        {
            try {
                $uri = [Uri]::New("https://" + $uri)
            } catch {
                # Could not convert with https:// prefix
            }
        }

        # If it's still not a URI, then fail the normalisation
        if ($uri.GetType().FullName -ne "System.Uri")
        {
            Write-Error ("Failed to convert object to uri directly or with https:// prefix: {0}" -f $uri)
        }

        # Ensure the URI is lowercase and the path is absent
        $tempUri = [Uri]::New($uri.AbsoluteUri.ToLower())
        $uri = [Uri]::New(("{0}://{1}:{2}" -f $tempUri.Scheme, $tempUri.Host, $tempUri.Port))

        # Pass the Uri on
        if ($AsString)
        {
            $uri.ToString()
        } else {
            $uri
        }
    }
}

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
        [AllowNull()]
        [AllowEmptyCollection()]
        [PSCustomObject[]]$Extensions
    )

    process
    {
        # Handle an empty extensions list
        if (($Extensions | Measure-Object).Count -eq 0)
        {
            [string]::Empty
            return
        }

        $content = $Extensions |
            Where-Object { $null -ne $_ -and $_.Oid -eq $Oid } |
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

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [string]$Sni,

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

            try {
                # Configure the SslStream connection
                $stream = $null
                if ($NoValidation)
                {
                    $stream = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false, ([ServerCertificateValidationCallback]::IgnoreCertificateValidation)
                } else {
                    $stream = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false
                }

                # This supplies the SNI to the endpoint
                Write-Verbose ("{0}: Sending SNI as {1}" -f $Uri, $Sni)
                $sslConnect = $stream.AuthenticateAsClientAsync($Sni)
                $sslConnect.Wait($TimeoutSec * 1000) | Out-Null

                if (!$sslConnect.IsCompleted)
                {
                    # Connected but failed to perform TLS negotiation
                    Write-Error "Failed to negotiate TLS with endpoint"
                }

                # Capture the remote certificate from the stream
                Write-Verbose ("{0}: Retrieving remote certificate" -f $Uri)
                $status.Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($stream.RemoteCertificate)

                # Update status
                $status.AuthSuccess = $true
            } catch {
                $status.Error = "Failed to negotiate TLS: $_"
            } finally {
                if ($null -ne $stream)
                {
                    $stream.Dispose()
                }
            }
        } catch {
            $status.Error = "Failed to connect: $_"
        } finally {
            if ($null -ne $client)
            {
                $client.Dispose()
            }
        }

        # Return status object
        $status
    }
}

<#
#>
Function Test-EndpointCertificate
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '')]
    [CmdletBinding(DefaultParameterSetName="NoPipe")]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline, Position=0)]
        [ValidateNotNull()]
        $Connection,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [string]$Sni = "",

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Int]$ConcurrentChecks = 30,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [Int]$TimeoutSec = 10,

        [Parameter(Mandatory=$false)]
        [switch]$AsHashTable = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$LogProgressSec = 0
    )

    begin
    {
        # We'll verbose report on the total run time later on
        $beginTime = [DateTime]::UtcNow

        # Hang threshold
        $hangThresholdSec = $TimeoutSec * 2
        if ($hangThresholdSec -lt 60)
        {
            $hangThresholdSec = 60
        }

        # State object to assist with managing runspaces
        $state = [PSCustomObject]@{
            runspaces = New-Object System.Collections.Generic.List[PSCustomObject]
            AsHashTable = $AsHashTable
            Completed = 0
            Hung = 0
            LastProgress = [DateTime]::UtcNow
            BeginTime = $beginTime
            LogProgressSec = $LogProgressSec
            TimeoutSec = $TimeoutSec
            HangThresholdSec = $hangThresholdSec
        }

        # Create a list of endpoints we've scheduled for checking to avoid duplicates
        # passed in by pipeline
        $scheduled = New-Object 'System.Collections.generic.HashSet[string]'
    }

    process
    {
        # Wait for job level to go under ConcurrentChecks
        Wait-CertCheckRunspaces -State $state -target ($ConcurrentChecks-1)

        # Object representing the target of the check
        $conn = [PSCustomObject]@{
            Connection = $null
            Sni = $null
        }

        & {
            # Check if we have a Uri object
            if ($Connection.GetType().FullName -eq "System.Uri")
            {
                $conn.Connection = $Connection.AbsoluteUri.ToString()
                $conn.Sni = $Connection.Host.ToString()
                return
            }

            # If it's a HashTable, check for relevant keys
            if ($Connection.GetType().FullName -eq "System.Collections.Hashtable")
            {
                try { $conn.Connection = $Connection["Uri"].ToString() } catch {}
                try { $conn.Connection = $Connection["Connection"].ToString() } catch {}
                try { $conn.Sni = $Connection["Sni"].ToString() } catch {}

                return
            }

            # If it's a custom object, check for members
            if ($Connection.GetType().FullName -eq "System.Management.Automation.PSCustomObject")
            {
                try { $conn.Connection = $Connection.Uri.ToString() } catch {}
                try { $conn.Connection = $Connection.Connection.ToString() } catch {}
                try { $conn.Sni = $Connection.Sni.ToString() } catch {}

                return
            }

            # See if we can convert it to a uri object
            try {
                $uri = New-NormalisedUri $Connection

                # Success - Use this object
                $conn.Connection = $uri.ToString()
                $conn.Sni = $uri.Host.ToString()
                return
            } catch {
            }
        }

        # Normalise the Uri
        try {
            $conn.Connection = New-NormalisedUri $conn.Connection -AsString
        } catch {
            Write-Warning ("Could not normalise the Uri ({0}): {1}" -f $conn.Connection, $_)
            return
        }

        # Configure Sni, if there is a 'Connection' value, but no Sni
        if (![string]::IsNullOrEmpty($conn.Connection) -and [string]::IsNullOrEmpty($conn.Sni))
        {
            try {
                $conn.Sni = ([Uri]::New($conn.Connection)).Host
            }
            catch {
            }
        }

        # If SNI was provided, unconditionally set the Sni to that, regardless of
        # what has been determined above
        if (![string]::IsNullOrEmpty($Sni))
        {
            $conn.Sni = $Sni
        }

        # Make sure we have something valid to continue
        if ([string]::IsNullOrEmpty($conn.Connection) -or [string]::IsNullOrEmpty($conn.Sni))
        {
            Write-Warning ("Could not convert incoming object or invalid inputs: {0}" -f $Connection)
            return
        }

        # Check if this combination of connection and uri is already in the scheduled list
        # and don't check, if it is already present
        $key = $conn.Connection + ":" + $conn.Sni
        if ($scheduled.Contains($key))
        {
            return
        }

        # Record that we've scheduled a check for this
        $scheduled.Add($key) | Out-Null

        # Create a new runspace to perform the check for this connection and sni
        $runspace = New-CertCheckRunspace -Connection $conn.Connection -Sni $conn.Sni -TimeoutSec $TimeoutSec
        $state.runspaces.Add($runspace)
    }

    end
    {
        # Wait for all runspaces to finish
        Write-Verbose "Waiting for remainder of runspaces to finish"
        Wait-CertCheckRunspaces -State $state -Target 0

        # Log progress completed
        Write-Progress -Id 1 -Activity "Endpoint Check" -Completed

        Write-Verbose ("Total runtime: {0} seconds" -f ([DateTime]::UtcNow - $beginTime).TotalSeconds)
    }
}

Function New-CertCheckRunspace
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Connection,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Sni,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [int]$TimeoutSec
    )

    process
    {
        # Initial session state for the check script. This is to import functions in to the
        # creates runspaces
        $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        @("Get-CertificateData", "Get-CertificateExtension") | ForEach-Object {
            $content = Get-Content Function:\$_ | Out-String
            $function = [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::New($_, $content)
            $initialSessionState.Commands.Add($function)
        }

        # Endpoint check script
        $checkScript = {
            param($Connection, $Sni, $TimeoutSec)

            $InformationPreference = "Continue"
            $ErrorActionPreference = "Stop"
            Set-StrictMode -Version 2

            & {
                # Build status object
                $status = @{
                    Connection = $Connection
                    Sni = $Sni
                    Connected = $false
                    Subject = ""
                    Issuer = ""
                    NotBefore = [DateTime]::MinValue
                    NotAfter = [DateTime]::MinValue
                    Thumbprint = ""
                    LocallyTrusted = $false
                    Extensions = ""
                    SAN = ""
                    EKU = ""
                    BasicConstraints = ""
                    RawData = ""
                    Addresses = ""
                    CertPath = ""
                    ErrorMsg = ""
                }

                # Uri object for connection
                $uri = [Uri]$Connection

                $chain = $null
                try {
                    # Get-CertificateData doesn't throw errors, just returns the status object
                    # Attempt to connect with certificate validation on first attempt
                    $connectStatus = Get-CertificateData -Uri $Connection -Sni $Sni -TimeoutSec $TimeoutSec

                    # If we can't connect, just stop here
                    if (!$connectStatus.Connected)
                    {
                        Write-Verbose "Could not connect to endpoint"
                        Write-Error $connectStatus.Error
                    }

                    $failedAuth = $false
                    if (!$connectStatus.AuthSuccess -or $null -eq $connectStatus.Certificate)
                    {
                        # We connected, but failed authentication or didn't receive a certificate
                        # Attempt to reconnect, but without validation of certificates
                        Write-Verbose "Validation of remote endpoint failed. Reattempting without validation."
                        $connectStatus = Get-CertificateData -Uri $Connection -Sni $Sni -TimeoutSec $TimeoutSec -NoValidation
                        $failedAuth = $true
                    }

                    if (!$connectStatus.AuthSuccess -or !$connectStatus.Connected -or $null -eq $connectStatus.Certificate -or ![string]::IsNullOrEmpty($connectStatus.Error))
                    {
                        # Issue with connecting to the endpoint here. Can't continue
                        Write-Verbose "Endpoint connectivity or auth failure"
                        Write-Error $connectStatus.Error
                    }

                    $cert = $connectStatus.Certificate

                    # Convert the extensions to friendly names with data
                    Write-Verbose ("{0}: Unpacking certificate extensions" -f $Connection)
                    try {
                        $extensions = $cert.Extensions | Where-Object { $null -ne $_ } | ForEach-Object {
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
                    } catch {
                        Write-Error "Error unpacking extensions: $_"
                    }

                    # Pack the extensions in to a string object
                    try {
                        $extensionStr = ($extensions | ForEach-Object {
                            ("{0}({1}) = {2}{3}" -f $_.FriendlyName, $_.Oid, $_.Value, [Environment]::NewLine)
                        } | Out-String).TrimEnd([Environment]::NewLine)
                    } catch {
                        Write-Error "Error transforming extensions: $_"
                    }

                    # Get addresses for this endpoint
                    $addresses = [System.Net.DNS]::GetHostAddresses($uri.Host)

                    # Build chain information for this certificate
                    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::New()
                    $chain.Build($cert) | Out-Null
                    $certPath = ($chain.ChainElements |
                        ForEach-Object { $_.Certificate.Subject.ToString() + [Environment]::NewLine } |
                        Out-String).TrimEnd([Environment]::NewLine)

                    # Update the hashtable with the entries we want to update on the CertificateInfo object
                    Write-Verbose ("{0}: Updating object" -f $Connection)
                    $status["Connected"] = $true
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
                    $status["RawData"] = [System.Convert]::ToBase64String($cert.RawData)

                    $addressStr = ""
                    $addresses | ForEach-Object { $addressStr += ($_.ToString() + ", ") }
                    $addressStr = $addressStr.TrimEnd(", ")

                    $status["Addresses"] = $addressStr
                    $status["CertPath"] = $certPath
                    $status["ErrorMsg"] = [string]::Empty
                } catch {
                    # Write-Warning ("{0}: Failed to check endpoint: {1}" -f $Connection, $_)
                    $status["ErrorMsg"] = [string]$_
                } finally {
                    if ($null -ne $chain)
                    {
                        $chain.Dispose()
                    }
                }

                # Return the state object
                $status
            } *>&1
        }

        # Schedule a run for this uri
        Write-Verbose ("Scheduling check: {0}:{1}" -f $Connection, $Sni)
        $runspace = [PowerShell]::Create($initialSessionState)
        $runspace.AddScript($checkScript) | Out-Null
        $runspace.AddParameter("Connection", $Connection) | Out-Null
        $runspace.AddParameter("Sni", $Sni) | Out-Null
        $runspace.AddParameter("TimeoutSec", $TimeoutSec) | Out-Null

        [PSCustomObject]@{
            Runspace = $runspace
            Status = $runspace.BeginInvoke()
            StartTime = [DateTime]::UtcNow
            Connection = $conn.Connection
            Sni = $conn.Sni
        }
    }
}

<#
#>
Function Wait-CertCheckRunspaces
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [PSCustomObject]$State,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [int]$Target
    )

    process
    {
        while ($State.runspaces.Count -gt $Target)
        {
            # Separate tasks in to completed, in progress and hung
            $inProgressList = New-Object System.Collections.Generic.List[PSCustomObject]
            $completeList = New-Object System.Collections.Generic.List[PSCustomObject]
            $hungList = New-Object System.Collections.Generic.List[PSCustomObject]
            $State.runspaces | ForEach-Object {
                if ($_.Status.IsCompleted)
                {
                    $completeList.Add($_)
                    return
                }

                # If the runspace has been running less than the hang threshold, add to the list to review on next cycle
                if (([DateTime]::UtcNow - $_.StartTime).TotalSeconds -lt $State.HangThresholdSec)
                {
                    $inProgressList.Add($_)
                    return
                }

                # runspace is not complete and is considered to be hung as it has run over the threshold
                $hungList.Add($_)
            }

            # If nothing has completed, nothing else is in progress, so there are only hung runspaces left
            # then process the hung runspaces
            if ($completeList.Count -eq 0 -and $inProgressList.Count -eq 0 -and $hungList.Count -gt 0)
            {
                $hungList | ForEach-Object {
                    Write-Warning ("Runspace for {0}:{1} has hung. Stopping." -f $_.Connection, $_.Sni)
                    try {
                        $_.Runspace.Stop()
                    } catch {
                        Write-Warning "Error stopping runspace: $_"
                    }
                    $_.Runspace.Dispose()
                    $_.Runspace = $null
                    $_.Status = $null

                    Write-Warning ("Scheduling new runspace for {0}:{1}" -f $_.Connection, $_.Sni)
                    $newRunspace = New-CertCheckRunspace -Connection $_.Connection -Sni $_.Sni -TimeoutSec $State.TimeoutSec
                    $inProgressList.Add($newRunspace)
                }
            } else {
                # Otherwise, we'll just add them back in to the inprogress list
                $hungList | ForEach-Object { $inProgressList.Add($_) }
            }

            $State.runspaces = $inProgressList
            $State.Hung = $hungList.Count

            # Process completed runspaces
            $completeList | ForEach-Object {
                $runspace = $_

                # Record completed job
                $State.Completed++

                # Try to receive the job output, being the HashTable containing
                # the properties for the check
                try {
                    $result = $runspace.Runspace.EndInvoke($runspace.Status) | ForEach-Object {
                        # Filter out anything that isn't a hashtable, but report on it
                        if ($_.GetType().FullName -ne "System.Collections.Hashtable")
                        {
                            Write-Warning "Runspace returned additional data: $_"
                        } else {
                            $_
                        }
                    }

                    # Make sure we have a single Hashtable
                    $count = ($result | Measure-Object).Count
                    if ($count -ne 1)
                    {
                        Write-Error "Runspace returned $count Hashtables, should be 1"
                    }

                    # Pass the Hashtable on in the pipeline
                    if ($State.AsHashTable)
                    {
                        $result
                    } else {
                        [PSCustomObject]$result
                    }
                } catch {
                    Write-Warning "Error reading return from runspace: $_"
                    Write-Warning ($_ | Format-List -property * | Out-String)
                }

                # Make sure we remove the runspace now
                $runspace.Runspace.Dispose()
                $runspace.Runspace = $null
                $runspace.Status = $null
            }

            # Progress status
            $status = New-CertCheckProgressMessage -State $State

            # Write progress update
            Write-Progress -Id 1 -Activity "Endpoint Check" -Status $status

            if ($State.LogProgressSec -gt 0 -and $State.LastProgress.AddSeconds($State.LogProgressSec) -lt [DateTime]::UtcNow)
            {
                $State.LastProgress = [DateTime]::UtcNow
                Write-Information "Endpoint Check Status: $status"
            }

            Start-Sleep -Seconds 1
        }

        # If we're to log progress, the target is 0 and we've finished the wait loop, then log a final progress
        if ($State.LogProgressSec -gt 0 -and $target -eq 0)
        {
            $status = New-CertCheckProgressMessage -State $State
            Write-Information "Endpoint Check Status: $status"
        }
    }
}

<#
#>
Function New-CertCheckProgressMessage
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [PSCustomObject]$State
    )

    process
    {
        $runtime = ([DateTime]::UtcNow - $State.BeginTime).TotalSeconds
        $endpointsps = [Math]::Round($State.Completed / $runtime, 2)
        $status = ("Completed {0}/In Progress {1}/Hung {2}/Runtime {3} seconds/{4} p/s" -f $State.Completed,
            $State.runspaces.Count, $State.Hung, [Math]::Round($runtime, 2), $endpointsps)

        $status
    }
}
