<#
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$Profile
)

$ErrorActionPreference = "Stop"
. ./ps-cibootstrap/bootstrap.ps1

########
# Capture version information
$version = @($Env:GITHUB_REF, "v0.1.0") | Select-ValidVersions -First -Required

Write-Information "Version:"
$version

########
# Determine docker tags
$dockerTags = @()

if ($version.FullVersion -ne "0.1.0")
{
    $dockerTags += $version.FullVersion

    # Add additional tags, if not prerelease
    if (!$version.IsPrerelease)
    {
        $dockerTags += ("{0}" -f $version.Major)
        $dockerTags += ("{0}.{1}" -f $version.Major, $version.Minor)
        $dockerTags += ("{0}.{1}.{2}" -f $version.Major, $version.Minor, $version.Patch)
    }

    $dockerTags += "latest"
}

Write-Information "Docker Tags:"
$dockerTags | ConvertTo-Json

$dockerImageName = "archmachina/certcheck"

########
# Build stage
Invoke-CIProfile -Name $Profile -Steps @{

    lint = @{
        Script = {
            Use-PowershellGallery
            Install-Module PSScriptAnalyzer -Scope CurrentUser
            Import-Module PSScriptAnalyzer
            $results = Invoke-ScriptAnalyzer -IncludeDefaultRules -Recurse .
            if ($null -ne $results)
            {
                $results
                Write-Error "Linting failure"
            }
        }
    }

    build = @{
        Script = {
            # Template PowerShell module definition
            Write-Information "Templating CertCheck.psd1"
            Format-TemplateFile -Template source/CertCheck.psd1.tpl -Target source/CertCheck/CertCheck.psd1 -Content @{
                __FULLVERSION__ = $version.PlainVersion
            }

            # Trust powershell gallery
            Write-Information "Setup for access to powershell gallery"
            Use-PowerShellGallery

            # Install any dependencies for the module manifest
            Write-Information "Installing required dependencies from manifest"
            Install-PSModuleFromManifest -ManifestPath source/CertCheck/CertCheck.psd1

            # Test the module manifest
            Write-Information "Testing module manifest"
            Test-ModuleManifest source/CertCheck/CertCheck.psd1

            # Import modules as test
            Write-Information "Importing module"
            Import-Module ./source/CertCheck/CertCheck.psm1

            # Docker build
            Write-Information ("Building for {0}" -f $dockerImageName)
            Invoke-Native "docker" "build", "-f", "./source/Dockerfile", "-q", "-t", $dockerImageName, "./source"
        }
    }

    pr = @{
        Dependencies = $("lint", "build")
    }

    latest = @{
        Dependencies = $("lint", "build")
    }

    release = @{
        Dependencies = $("build")
        Script = {
            $owner = "archmachina"
            $repo = "ps-certcheck"

            $releaseParams = @{
                Owner = $owner
                Repo = $repo
                Name = ("Release " + $version.Tag)
                TagName = $version.Tag
                Draft = $false
                Prerelease = $version.IsPrerelease
                Token = $Env:GITHUB_TOKEN
            }

            Write-Information "Creating release"
            New-GithubRelease @releaseParams

            Publish-Module -Path ./source/CertCheck -NuGetApiKey $Env:NUGET_API_KEY

            # Attempt login to docker registry
            Write-Information "Attempting login for docker registry"
            Invoke-Native -Script { $Env:DOCKER_HUB_TOKEN | docker login --password-stdin -u archmachina docker.io }

            # Push docker images
            Write-Information "Pushing docker tags"
            $dockerTags | Select-Object -Unique | ForEach-Object {
                $tag = $_
                $path = ("{0}:{1}" -f $dockerImageName, $_)

                # Docker tag
                Write-Information ("Tagging build for {0}" -f $tag)
                Invoke-Native "docker" "tag", $dockerImageName, $path

                # Docker push
                Write-Information ("Docker push for for {0}" -f $path)
                Invoke-Native "docker" "push", $path
            }
        }
    }
}
