

<#
#>
Function Format-EndpointCategoryReport
{
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$CategoryTable,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$EndpointTable,

        [Parameter(Mandatory=$false)]
        [switch]$AsHTML = $false,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$InactiveThreshold = 180
    )

    process
    {
        # Ensure positive values
        $InactiveThreshold = [Math]::Abs($InactiveThreshold)

        # Determine appropriate newlint per format type
        $newline = [Environment]::Newline
        if ($AsHtml)
        {
            $newline = "<br />"
        }

        # Get a list of the categories and Uris to process
        $categoryMap = Get-CategoryUri -Table $CategoryTable | Group-Object -Property CategoryName -AsHashTable

        # Get all endpoints from Azure storage
        # Ignore endpoints that haven't connected within last x days
        $tempEndpointMap = Get-EndpointCertificate -Table $EndpointTable |
            Where-Object {$_.LastConnect -gt ([DateTime]::UtcNow.AddDays(-$InactiveThreshold))} |
            Group-Object -Property Uri -AsHashTable

        # Convert Uri objects to string representation
        $endpointMap = @{}
        $tempEndpointMap.Keys | ForEach-Object {
            $endpointMap[$_.ToString()] = $tempEndpointMap[$_]
        }

        # Merge maps together
        $map = @{}
        if ($null -ne $categoryMap)
        {
            $categoryMap.Keys | ForEach-Object {
                $categoryName = $_

                # Add an entry for this category name
                $map[$categoryName] = @{}

                # Iterate through each Uri
                $categoryMap[$categoryName] | ForEach-Object {
                    $uri = $_.Uri

                    # Add an entry for this Uri for this category
                    $map[$categoryName][$uri] = @()

                    # Find all endpoint entries that match this uri
                    if ($endpointMap.Keys -contains $uri)
                    {
                        $map[$categoryName][$uri] = $endpointMap[$uri]
                    }
                }
            }
        }

        # Write a section for each category name
        $report = $map.Keys | ForEach-Object {
            $categoryName = $_

            # Generate content for this section
            $content = $map[$categoryName].Keys | ForEach-Object {
                $uri = $_

                # Group by thumbprint and locallytrusted so they are easily distinguishable in the report
                $groups = $map[$categoryName][$uri] | Group-Object -Property Thumbprint,LocallyTrusted

                if (($groups | Measure-Object).Count -gt 0)
                {
                    $groups | ForEach-Object {
                        $group = $_.Group

                        # Base status in case we have no endpoint data
                        $status = [PSCustomObject]@{
                            Uri = $uri
                            Issues = ""
                            Perspectives = "No Data"
                            DaysRemaining = 0
                            LocallyTrusted = $false
                            Info = "No Data"
                            SurveyAge = "No Data"
                        }

                        # If we have endpoint data, add perspectives and other cert data
                        if (($group | Measure-Object).Count -gt 0)
                        {
                            $first = $group | Select-Object -First 1

                            # Add subject info
                            $info = "Subject: " + $first.Subject + $newline

                            # Add Issuer info
                            $info += "Issuer: " + $first.Issuer + $newline

                            # Add thumbprint info
                            $info += "Thumbprint: " + $first.Thumbprint + $newline

                            $status.Perspectives = $group | ForEach-Object { $_.Perspective } | Join-String -Separator ", "
                            $status.DaysRemaining = $first.DaysRemaining()
                            $status.LocallyTrusted = $first.LocallyTrusted
                            $status.Info = $info

                            if (!$first.LocallyTrusted -or $first.DaysRemaining() -lt 0)
                            {
                                $status.Issues = "INVALID"
                            } elseif ($first.DaysRemaining() -lt 14)
                            {
                                $status.Issues = "AT RISK"
                            } elseif ($first.DaysRemaining() -lt 30)
                            {
                                $status.Issues = "NEARING EXPIRY"
                            }

                            $status.SurveyAge = (([DateTime]::UtcNow - $first.LastConnect).TotalDays.ToString("0.0") + " days")
                        }

                        # Pass the status on in the pipeline
                        $status
                    }
                } else {
                    [PSCustomObject]@{
                        Uri = $uri
                        Issues = "NO INFO"
                        Perspectives = "No Data"
                        DaysRemaining = 0
                        LocallyTrusted = $false
                        Info = "No Data"
                        SurveyAge = "No Data"
                    }
                }
            } | Sort-Object -Property DaysRemaining

            Format-EndpointReportSection -Content $content -AsHtml $AsHtml -Title "Category: $_" -Description "Endpoint summary for $categoryName"
        }

        # Write out content for report
        $report | Format-EndpointReport -AsHtml $AsHtml -Title "Category Report"
    }
}

<#
#>
Function Format-EndpointCertificateReport
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$CategoryTable,

        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [Microsoft.Azure.Cosmos.Table.CloudTable]$EndpointTable,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$InactiveThreshold = 180,

        [Parameter(Mandatory=$false)]
        [ValidateNotNull()]
        [int]$DisconnectThreshold = 3,

        [Parameter(Mandatory=$false)]
        [switch]$AsHTML = $false,

        [Parameter(Mandatory=$false)]
        [switch]$ShowInaccessible = $false,

        [Parameter(Mandatory=$false)]
        [switch]$ShowInvalid = $false,

        [Parameter(Mandatory=$false)]
        [switch]$ShowExpiring = $false
    )

    process
    {
        # Ensure positive values
        $DisconnectThreshold = [Math]::Abs($DisconnectThreshold)
        $InactiveThreshold = [Math]::Abs($InactiveThreshold)

        # Get all endpoints from Azure storage
        # Ignore endpoints that haven't connected within last x days
        $endpoints = Get-EndpointCertificate -Table $EndpointTable |
            Where-Object {
                $_.LastConnect -ge ([DateTime]::UtcNow.AddDays(-$InactiveThreshold))
            }

        # Add category information to the endpoints
        $endpoints | Merge-EndpointCategory -CategoryTable $CategoryTable

        $content = & {
            if ($ShowInaccessible)
            {
                # Display endpoints that couldn't be contacted
                $results = $endpoints |
                    Where-Object { $_.LastConnect -lt ([DateTime]::UtcNow.AddDays(-$DisconnectThreshold)) } |
                    Sort-Object -Property NotAfter |
                    Select-Object -Property Uri,Categories,Perspective,Subject,LastAttempt,LastConnect,Connected,LastError,LastErrorMsg
                Format-EndpointReportSection -Content $results -AsHtml $AsHtml -Title "Inaccessible endpoints" -Description "Endpoints that have communicated within the last $InactiveThreshold days, but not within the last $DisconnectThreshold days"
            }

            # get all endpoint data where the endpoint could be queried
            $connected = $endpoints | Where-Object {$_.LastConnect -ge ([DateTime]::UtcNow.AddDays(-$DisconnectThreshold))}

            if ($ShowInvalid)
            {
                # Show endpoints with invalid certificates
                $results = $connected | Where-Object {$_.LocallyTrusted -eq $false -or $_.IsDateValid() -eq $false} |
                    Group-Object -Property Uri,Thumbprint |
                    ForEach-Object {
                        $group = $_

                        # Determine all perspectives
                        $perspectives = $group.Group | ForEach-Object { $_.Perspective } | Select-Object -Unique |
                            Join-String -Separator ", "

                        # Since thumbprint is the same for all in this group, we only need the cert information from the first object
                        $first = $group.Group | Select-Object -First 1

                        [PSCustomObject]@{
                            Uri = $first.Uri
                            Categories = $first.Categories
                            Perspectives = $perspectives
                            Subject = $first.Subject
                            Issuer = $first.Issuer
                            DaysRemaining = $first.DaysRemaining()
                            # Locally Trusted is perspective based, so not guaranteed to be the same between separate checkers,
                            # however this if filtered by 'LocallyTrusted -eq $false' above, so they should all be the same
                            LocallyTrusted = $first.LocallyTrusted
                        }
                    } | Sort-Object -Property DaysRemaining
                Format-EndpointReportSection -Content $results -AsHtml $AsHtml -Title "Invalid certificates" -Description "Endpoints with an invalid certificate (untrusted or date out of range)"
            }

            if ($ShowExpiring)
            {
                # Show endpoints expiring soon
                $results = $connected | Where-Object {
                        $_.NotAfter -lt ([DateTime]::UtcNow.AddDays(60)) -and $_.NotAfter -gt ([DateTime]::UtcNow.AddDays(-14))
                    } |
                    Group-Object -Property Uri,Thumbprint | ForEach-Object {
                        $group = $_

                        # Determine all perspectives
                        $perspectives = $group.Group | ForEach-Object { $_.Perspective } | Select-Object -Unique |
                            Join-String -Separator ", "

                        # Since thumbprint is the same for all in this group, we only need the cert information from the first object
                        $first = $group.Group | Select-Object -First 1

                        [PSCustomObject]@{
                            Uri = $first.Uri
                            Categories = $first.Categories
                            Perspectives = $perspectives
                            Subject = $first.Subject
                            Issuer = $first.Issuer
                            DaysRemaining = $first.DaysRemaining()
                            NotAfter = $first.NotAfter
                            # LocallyTrusted is not included here as it may be different between checkers depending on
                            # local trusted CA configuration
                            # LocallyTrusted = $first.LocallyTrusted
                        }
                    } | Sort-Object -Property NotAfter
                Format-EndpointReportSection -Content $results -AsHtml $AsHtml -Title "Endpoints expiring soon" -Description "All endpoints expiring within 60 days (Locally trusted or not)"
            }
        }

        # Write out content for report
        $content | Format-EndpointReport -AsHtml $AsHtml -Title "Endpoint Report"
    }
}
