<#
#>

########
# Global settings
$ErrorActionPreference = "Stop"
$InformationPreference = "Continue"
Set-StrictMode -Version 2

<#
#>
Function New-NormalisedUri
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        $UriObj,

        [Parameter(Mandatory=$false)]
        [switch]$AsString = $false
    )

    process
    {
        # If it's not a URI, attempt to convert to Uri directly
        $uri = $UriObj
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

            # Configure the SslStream connection
            $stream = $null
            if ($NoValidation)
            {
                $stream = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false, $certValidation
            } else {
                $stream = New-Object System.Net.Security.SslStream -ArgumentList $client.GetStream(), $false
            }

            # This supplies the SNI to the endpoint
            Write-Verbose ("{0}: Sending SNI as {1}" -f $Uri, $Sni)
            $stream.AuthenticateAsClient($Sni)

            # Update status
            $status.AuthSuccess = $true

            # Capture the remote certificate from the stream
            Write-Verbose ("{0}: Retrieving remote certificate" -f $Uri)
            $status.Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($stream.RemoteCertificate)
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

<#
#>
Function Test-EndpointCertificate
{
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
        [switch]$AsHashTable = $false
    )

    begin
    {
        # We'll verbose report on the total run time later on
        $beginTime = [DateTime]::UtcNow

        # Initial session state for the check script. This is to import functions in to the
        # creates runspaces
        $initialSessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        @("Get-CertificateData", "Get-CertificateExtension") | ForEach-Object {
            $content = Get-Content Function:\$_ | Out-String
            $function = [System.Management.Automation.Runspaces.SessionStateFunctionEntry]::New($_, $content)
            $initialSessionState.Commands.Add($function)
        }

        # Use a custom object so the wait block can replace the list with a new list
        # (i.e. update the reference)
        $state = [PSCustomObject]@{
            runspaces = New-Object System.Collections.Generic.List[PSCustomObject]
            AsHashTable = $AsHashTable
        }

        # Create a list of endpoints we've scheduled for checking to avoid duplicates
        # passed in by pipeline
        $scheduled = New-Object 'System.Collections.generic.HashSet[string]'

        # Common wait block to use to process finished jobs
        # $target is the is the high count before we can schedule more checks
        $waitScript = {
            param($state, $target)

            while (($state.runspaces | Measure-Object).Count -gt $target)
            {
                # Separate tasks in to 'completed' and not
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

                    # Try to receive the job output, being the HashTable containing
                    # the properties for the check
                    try {
                        $result = $runspace.Runspace.EndInvoke($runspace.Status) | Select-Object -First 1

                        if ($state.AsHashTable)
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
                    $runspace.Status = $null
                }

                Start-Sleep -Seconds 1
            }
        }
    }

    process
    {
        # Wait for job level to go under ConcurrentChecks
        Invoke-Command -Script $waitScript -ArgumentList $state, ($ConcurrentChecks-1)

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

        $scheduled.Add($key) | Out-Null

        # Endpoint check script
        $checkScript = {
            param($Connection, $Sni, $TimeoutSec)

            $InformationPreference = "Continue"
            $ErrorActionPreference = "Stop"
            Set-StrictMode -Version 2

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

            try {
                # Get-CertificateData doesn't throw errors, just returns the status object
                # Attempt to connect with certificate validation on first attempt
                $connectStatus = Get-CertificateData -Uri $Connection -Sni $Sni -TimeoutSec $TimeoutSec

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
            }

            # Return the state object
            $status
        }

        # Schedule a run for this uri
        Write-Verbose ("Scheduling check: {0}:{1}" -f $conn.Connection, $conn.Sni)
        $runspace = [PowerShell]::Create($initialSessionState)
        $runspace.AddScript($checkScript) | Out-Null
        $runspace.AddParameter("Connection", $conn.Connection) | Out-Null
        $runspace.AddParameter("Sni", $conn.Sni) | Out-Null
        $runspace.AddParameter("TimeoutSec", $TimeoutSec) | Out-Null

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

        Write-Verbose ("Total runtime: {0} seconds" -f ([DateTime]::UtcNow - $beginTime).TotalSeconds)
    }
}
