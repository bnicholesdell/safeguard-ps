<#
.SYNOPSIS
Upload trusted certificate to Safeguard via the Web API.

.DESCRIPTION
Upload a certificate to serve as a new trusted root certificate for
Safeguard. You use this same method to upload an intermediate
certificate that is part of the chain of trust.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a certificate in DER or Base64 format.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Install-SafeguardTrustedCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Install-SafeguardTrustedCertificate "\\someserver.corp\share\Cert Root CA.cer"
#>
function Install-SafeguardTrustedCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    $local:CertificateContents = (Get-CertificateFileContents $CertificateFile)
    if (-not $CertificateContents)
    {
        throw "No valid certificate to upload"
    }

    Write-Host "Uploading Certificate..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST TrustedCertificates -Body @{
            Base64CertificateData = "$($local:CertificateContents)"
        }
}

<#
.SYNOPSIS
Remove trusted certificate from Safeguard via the Web API.

.DESCRIPTION
Remove a trusted certificate that was previously added to Safeguard via
the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Uninstall-SafeguardTrustedCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Uninstall-SafeguardTrustedCertificate -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA
#>
function Uninstall-SafeguardTrustedCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        $local:CurrentThumbprints = (Get-SafeguardTrustedCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Thumbprint -join ", "
        Write-Host "Currently Installed Trusted Certificates: [ $($local:CurrentThumbprints) ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "TrustedCertificates/$Thumbprint"
}

<#
.SYNOPSIS
Get trusted certificates from Safeguard via the Web API.

.DESCRIPTION
Retrieve trusted certificates that were previously added to Safeguard via
the Web API.  These will be only the user-added trusted certificates.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the certificate.

.PARAMETER Fields
An array of the certificate property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardTrustedCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardTrustedCertificate
#>
function Get-SafeguardTrustedCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("Thumbprint"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "TrustedCertificates/$Thumbprint" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET TrustedCertificates  -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Get the audit log signing certificate from Safeguard via the Web API.

.DESCRIPTION
Retrieve the certificate used for signing the audit log via the Web API.
This certificate is used to sign the audit log when it is exported for long-term
retention.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Fields
An array of the certificate property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAuditLogSigningCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardAuditLogSigningCertificate
#>
function Get-SafeguardAuditLogSigningCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        GET "AuditLog/Retention/SigningCertificate" -Parameters $local:Parameters
}

<#
.SYNOPSIS
Upload audit log signing certificate to Safeguard via the Web API.

.DESCRIPTION
Upload a certificate for signing the audit log when exported for long-term
retention.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a certificate PFX or P12 file.

.PARAMETER Password
A secure string to be used as a passphrase for the certificate PFX or P12 file.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Install-SafeguardAuditLogSigningCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Install-SafeguardAuditLogSigningCertificate -CertificateFile C:\cert.pfx

.EXAMPLE
Install-SafeguardAuditLogSigningCertificate -CertificateFile C:\cert.pfx -Password (ConvertTo-SecureString -AsPlainText "TestPassword" -Force)
#>
function Install-SafeguardAuditLogSigningCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false,Position=1)]
        [SecureString]$Password
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    $local:CertificateContents = (Get-CertificateFileContents $CertificateFile)
    if (-not $CertificateContents)
    {
        throw "No valid certificate to upload"
    }

    if (-not $Password)
    {
        Write-Host "For no password just press enter..."
        $Password = (Read-host "Password" -AsSecureString)
    }
    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password

    Write-Host "Uploading Certificate..."
    if ($local:PasswordPlainText)
    {
        $local:NewCertificate = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "AuditLog/Retention/SigningCertificate" -Body @{
                Base64CertificateData = "$($local:CertificateContents)";
                Passphrase = "$($local:PasswordPlainText)"
            })
    }
    else
    {
        $local:NewCertificate = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            PUT "AuditLog/Retention/SigningCertificate" -Body @{
                Base64CertificateData = "$($local:CertificateContents)"
            })
    }

    $local:NewCertificate
}

<#
.SYNOPSIS
Remove audit log signing certificate from Safeguard via the Web API.

.DESCRIPTION
Remove the certificate for signing the audit log when exported for long-term
retention.  It will be replaced by the default.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Uninstall-SafeguardAuditLogSigningCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Uninstall-SafeguardAuditLogSigningCertificate
#>
function Uninstall-SafeguardAuditLogSigningCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "AuditLog/Retention/SigningCertificate"
}

<#
.SYNOPSIS
Upload SSL certificate to Safeguard appliance via the Web API.

.DESCRIPTION
Upload a certificate for use with SSL server authentication. A separate
action is required to assign an SSL certificate to a particular appliance if
you do not use the -Assign parameter. A certificate can be assigned using
the Set-SafeguardSslCertificateForAppliance cmdlet.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateFile
A string containing the path to a certificate PFX or P12 file.

.PARAMETER Password
A secure string to be used as a passphrase for the certificate PFX or P12 file.

.PARAMETER Assign
Install the certificate to this server immediately.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Install-SafeguardSslCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Install-SafeguardSslCertificate -CertificateFile C:\cert.pfx
#>
function Install-SafeguardSslCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false,Position=1)]
        [SecureString]$Password,
        [Parameter(Mandatory=$false)]
        [switch]$Assign
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    $local:CertificateContents = (Get-CertificateFileContents $CertificateFile)
    if (-not $CertificateContents)
    {
        throw "No valid certificate to upload"
    }

    if (-not $Password)
    {
        Write-Host "For no password just press enter..."
        $Password = (Read-host "Password" -AsSecureString)
    }
    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password

    Write-Host "Uploading Certificate..."
    if ($local:PasswordPlainText)
    {
        $local:NewCertificate = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST SslCertificates -Body @{
                Base64CertificateData = "$($local:CertificateContents)";
                Passphrase = "$($local:PasswordPlainText)"
            })
    }
    else
    {
        $local:NewCertificate = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            POST SslCertificates -Body @{
                Base64CertificateData = "$($local:CertificateContents)"
            })
    }

    $local:NewCertificate

    if ($Assign -and $local:NewCertificate.Thumbprint)
    {
        Set-SafeguardSslCertificateForAppliance -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure $local:NewCertificate.Thumbprint
    }
}

<#
.SYNOPSIS
Remove SSL certificate from Safeguard via the Web API.

.DESCRIPTION
Remove an SSL certificate that was previously added to Safeguard via
the Web API.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Uninstall-SafeguardSslCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Uninstall-SafeguardSslCertificate -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA
#>
function Uninstall-SafeguardSslCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        $local:CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $($local:CurrentThumbprints) ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "SslCertificates/$Thumbprint"
}

<#
.SYNOPSIS
Get SSL certificates from Safeguard via the Web API.

.DESCRIPTION
Retrieve SSL certificates that were previously added to Safeguard via
the Web API.  These will also include the default SSL certificates.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the certificate.

.PARAMETER Fields
An array of the certificate property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSslCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardSslCertificate
#>
function Get-SafeguardSslCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("Thumbprint"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "SslCertificates/$Thumbprint" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET SslCertificates -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Assign an SSL certificate to a specific Safeguard appliance via the Web API.

.DESCRIPTION
Assign a previously added SSL certificate to a specific Safeguard appliance via
the Web API.  If an appliance ID is not specified this cmdlet will use the appliance
that you are communicating with.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the SSL certificate.

.PARAMETER ApplianceId
A string containing the ID of the appliance to assign the SSL certificate to.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Set-SafeguardSslCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Set-SafeguardSslCertificateForAppliance -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA -ApplianceId 00155D26E342
#>
function Set-SafeguardSslCertificateForAppliance
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        $local:CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $($local:CurrentThumbprints) ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    if (-not $ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status).ApplianceId
    }


    Write-Host "Setting $Thumbprint as current SSL Certificate for $ApplianceId..."
    $local:CurrentIds = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "SslCertificates/$Thumbprint/Appliances")
    if (-not $local:CurrentIds)
    {
        $local:CurrentIds = @()
    }
    $local:CurrentIds += @{ "Id" = "$ApplianceId" }
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "SslCertificates/$Thumbprint/Appliances" -Body $local:CurrentIds
}

<#
.SYNOPSIS
Unassign SSL certificate from a Safeguard appliance via the Web API.

.DESCRIPTION
Unassign SSL certificate from a Safeguard appliance that was previously
configured via the Web API.  If an appliance ID is not specified to this
cmdlet will use the appliance that you are communicating with.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of the SSL certificate.

.PARAMETER ApplianceId
A string containing the ID of the appliance to unassign the SSL certificate from.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Clear-SafeguardSslCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Clear-SafeguardSslCertificateForAppliance -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA -ApplianceId 00155D26E342
#>
function Clear-SafeguardSslCertificateForAppliance
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Thumbprint)
    {
        $local:CurrentThumbprints = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure).Thumbprint -join ", "
        Write-Host "Currently Installed SSL Certificates: [ $($local:CurrentThumbprints) ]"
        $Thumbprint = (Read-Host "Thumbprint")
    }

    if (-not $ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status).ApplianceId
    }

    Write-Host "Clearing $Thumbprint as current SSL Certificate for $ApplianceId..."
    $local:CurrentIds = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "SslCertificates/$Thumbprint/Appliances")
    $local:NewIds = $local:CurrentIds | Where-Object { $_.Id -ne $ApplianceId }
    if (-not $local:NewIds)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "SslCertificates/$Thumbprint/Appliances" -JsonBody "[]"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "SslCertificates/$Thumbprint/Appliances" -Body $local:NewIds
    }
}

<#
.SYNOPSIS
Get SSL certificate assigned to a specific Safeguard via the Web API.

.DESCRIPTION
Get the SSL certificate that has been previously assigned to a specific
Safeguard appliance.  If an appliance ID is not specified to this cmdlet
will use the appliance that you are communicating with.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER ApplianceId
A string containing the ID of the appliance he SSL certificate is assigned to.

.PARAMETER Fields
An array of the certificate property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardSslCertificateForAppliance -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardSslCertificateForAppliance -ApplianceId 00155D26E342
#>
function Get-SafeguardSslCertificateForAppliance
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=1)]
        [string]$ApplianceId,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $ApplianceId)
    {
        $ApplianceId = (Invoke-SafeguardMethod -Anonymous -Appliance $Appliance -Insecure:$Insecure Notification GET Status).ApplianceId
    }

    $local:Certificates = (Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Fields Thumbprint)
    $local:Certificates | ForEach-Object {
        if (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "SslCertificates/$($_.Thumbprint)/Appliances" | Where-Object {
            $_.Id -eq $ApplianceId
        })
        {
            Get-SafeguardSslCertificate -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure -Thumbprint $_.Thumbprint -Fields $Fields
        }
    }
}

<#
.SYNOPSIS
Get certificate signing requests that have been generated for Safeguard via the Web API.

.DESCRIPTION
Safeguard can generate certificate signing requests (CSRs) so that private keys never
leave the system.  These CSRs can be created for 1) server-side SSL covering the web client
and web API, 2) RDP connection signing for RDP session proxy, 3) Timestamping authority for
adding trusted timestamps to session recordings, and 4) session recording signing for adding
signatures to session recordings to prove they came from Safeguard.

This cmdlet gets CSRs that are currently outstanding but that have not yet been signed and
returned to Safeguard.  Stale CSRs can be deleted via Delete-SafeguardCertificateSigningRequest.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of a specific CSR.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardCertificateSigningRequest -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardCertificateSigningRequest D7B8FB86C277BB173E29E368532D8B00E30DBC67
#>
function Get-SafeguardCertificateSigningRequest
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(ParameterSetName="Single",Mandatory=$true,Position=0)]
        [string]$Thumbprint
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("Thumbprint"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ServerCertificateSignatureRequests/$Thumbprint"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core GET "ServerCertificateSignatureRequests"
    }
}
New-Alias -Name Get-SafeguardCsr -Value Get-SafeguardCertificateSigningRequest

<#
.SYNOPSIS
Create a certificate signing request in Safeguard via the Web API.

.DESCRIPTION
Safeguard can generate certificate signing requests (CSRs) so that private keys never
leave the system.  These CSRs can be created for 1) server-side SSL covering the web client
and web API, 2) RDP connection signing for RDP session proxy, 3) Timestamping authority for
adding trusted timestamps to session recordings, and 4) session recording signing for adding
signatures to session recordings to prove they came from Safeguard.

This cmdlet creates new CSRs that .  Stale CSRs can be deleted via Delete-SafeguardCertificateSigningRequest.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateType
A string containing the type of CSR.

.PARAMETER Subject
A string containing the distinguished name of the subject of the CSR.

.PARAMETER KeyLength
An integer containing the key length (1024, 2048, 3072, 4096, default: 2048).

.PARAMETER IpAddresses
An array of strings containing IP addresses to use in subject alternative names.

.PARAMETER DnsNames
An array of strings containing DNS names to use in subject alternative names.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardCertificateSigningRequest -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
New-SafeguardCertificateSigningRequest Ssl "CN=Safeguard,O=OneIdentity" -DnsNames "safeguard.oneidentity.com" -IpAddresses "10.10.10.10"

.EXAMPLE
New-SafeguardCertificateSigningRequest SessionRecording "CN=SessionSign,O=OneIdentity" sessionsign.csr
#>
function New-SafeguardCertificateSigningRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [ValidateSet('Ssl', 'TimeStamping', 'RdpSigning', 'SessionRecording', 'AuditLogSigning')]
        [string]$CertificateType,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Subject,
        [Parameter(Mandatory=$false)]
        [ValidateSet(1024, 2048, 3072, 4096)]
        [int]$KeyLength = 2048,
        [Parameter(Mandatory=$false)]
        [string[]]$IpAddresses = $null,
        [Parameter(Mandatory=$false)]
        [string[]]$DnsNames = $null,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$OutFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{
        CertificateType = $CertificateType;
        Subject = $Subject;
        KeyLength = $KeyLength
    }

    if ($PSBoundParameters.ContainsKey("IpAddresses"))
    {
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        $IpAddresses | ForEach-Object {
            if (-not (Test-IpAddress $_))
            {
                throw "$_ is not an IP address"
            }
        }
        $local:Body.IpAddresses = $IpAddresses
    }
    if ($PSBoundParameters.ContainsKey("DnsNames")) { $local:Body.DnsNames = $DnsNames }

    $local:Csr = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "ServerCertificateSignatureRequests" -Body $local:Body)
    $local:Csr
    $local:Csr.Base64RequestData | Out-File -Encoding ASCII -FilePath $OutFile -NoNewline
    Write-Host "CSR saved to '$OutFile'"
}
New-Alias -Name New-SafeguardCsr -Value New-SafeguardCertificateSigningRequest

<#
.SYNOPSIS
Delete a certificate signing request that has been generated for Safeguard via the Web API.

.DESCRIPTION
Safeguard can generate certificate signing requests (CSRs) so that private keys never
leave the system.  These CSRs can be created for 1) server-side SSL covering the web client
and web API, 2) RDP connection signing for RDP session proxy, 3) Timestamping authority for
adding trusted timestamps to session recordings, and 4) session recording signing for adding
signatures to session recordings to prove they came from Safeguard.

This cmdlet may be used to delete stale CSRs that have not yet been signed and will never be
returned to Safeguard.  You can find stale CSRs using Get-SafeguardCertificateSigningRequest.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Thumbprint
A string containing the thumbprint of a specific CSR.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardCertificateSigningRequest D7B8FB86C277BB173E29E368532D8B00E30DBC67
#>
function Remove-SafeguardCertificateSigningRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$Thumbprint
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "ServerCertificateSignatureRequests/$Thumbprint"
}
New-Alias -Name Remove-SafeguardCsr -Value Remove-SafeguardCertificateSigningRequest

<#
.SYNOPSIS
Create test certificates for use with Safeguard.

.DESCRIPTION
Creates test certificates for use with Safeguard.  This cmdlet will create
a new root CA, an intermediate CA, a user certificate, and a server SSL
certificate.  The user certificate can be used for login.  The SSL certificate
can be used to secure Safeguard.

.PARAMETER SubjectBaseDn
A string containing the subject base Dn (e.g. "").

.PARAMETER KeySize
An integer with the RSA key size.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate--will be ignored for entire session.

.INPUTS
None.

.OUTPUTS
None.  Just host messages describing what has been created.

.EXAMPLE
New-SafeguardTestCertificates -SubjectBaseDn "OU=petrsnd,O=OneIdentityInc,C=US"

.EXAMPLE
New-SafeguardTestCertificates
#>
function New-SafeguardTestCertificatePki
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true)]
        [string]$SubjectBaseDn,
        [Parameter(Mandatory=$false)]
        [int]$KeySize = 2048,
        [Parameter(Mandatory=$false)]
        $OutputDirectory
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }
    Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local

    if (-not $OutputDirectory)
    {
        $OutputDirectory = (Join-Path (Get-Location) ("CERTS-{0}" -f (Get-Date -format s) -replace ':','-'))
    }
    else
    {
        $OutputDirectory = (Join-Path $OutputDirectory ("CERTS-{0}" -f (Get-Date -format s) -replace ':','-'))
    }

    Write-Host -ForegroundColor Yellow "Locating tools"
    $local:MakeCert = (Get-Tool @("C:\Program Files (x86)\Windows Kits", "C:\Program Files (x86)\Microsoft SDKs\Windows") "makecert.exe")
    $local:Pvk2Pfx = (Get-Tool @("C:\Program Files (x86)\Windows Kits", "C:\Program Files (x86)\Microsoft SDKs\Windows") "pvk2pfx.exe")
    $local:CertUtil = (Join-Path $env:windir "system32\certutil.exe")

    Write-Host "Creating Directory: $OutputDirectory"
    New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

    Write-Host -ForegroundColor Yellow "Generating Certificates"
    Write-Host "This cmdlet can be annoying because you have to type your password a lot... this is a limitation of the underlying tools"
    Write-Host -ForegroundColor Yellow "Just type the same password at all of the prompts!!! It can be as simple as one letter."
    $local:PasswordSecure = (Read-Host "Password" -AsSecureString)
    $local:Password = [System.Net.NetworkCredential]::new("", $local:PasswordSecure).Password

    $local:Name = "RootCA"
    $local:Subject = "CN=$($local:Name),$($local:SubjectBaseDn)"
    Write-Host "Creating Root CA Certificate as $($local:Subject)"
    Invoke-Expression ("& '$($local:MakeCert)' -n '$($local:Subject)' -r -a sha256 -len $($local:KeySize) -m 240 -cy authority -sky signature -sv '$OutputDirectory\$($local:Name).pvk' '$OutputDirectory\$($local:Name).cer'")
    Invoke-Expression ("& '$($local:CertUtil)' -encode '$OutputDirectory\$($local:Name).cer' '$OutputDirectory\$($local:Name).pem'")
    Invoke-Expression ("& '$($local:Pvk2Pfx)' -pvk '$OutputDirectory\$($local:Name).pvk' -spc '$OutputDirectory\$($local:Name).cer' -pfx '$OutputDirectory\$($local:Name).pfx' -pi $($local:Password)")

    $local:Issuer = "RootCA"
    $local:Name = "IntermediateCA"
    $local:Subject = "CN=$($local:Name),$SubjectBaseDn"
    Write-Host "Creating Intermediate CA Certificate as $($local:Subject)"
    Invoke-Expression ("& '$($local:MakeCert)' -n '$($local:Subject)' -a sha256 -len $KeySize -m 240 -cy authority -sky signature -iv '$OutputDirectory\$($local:Issuer).pvk' -ic '$OutputDirectory\$($local:Issuer).cer' -sv '$OutputDirectory\$($local:Name).pvk' '$OutputDirectory\$($local:Name).cer'")
    Invoke-Expression ("& '$($local:CertUtil)' -encode '$OutputDirectory\$($local:Name).cer' '$OutputDirectory\$($local:Name).pem'")
    Invoke-Expression ("& '$($local:Pvk2Pfx)' -pvk '$OutputDirectory\$($local:Name).pvk' -spc '$OutputDirectory\$($local:Name).cer' -pfx '$OutputDirectory\$($local:Name).pfx' -pi $($local:Password)")

    $local:Issuer = "IntermediateCA"
    $local:Name = "UserCert"
    $local:Subject = "CN=$($local:Name),$SubjectBaseDn"
    Write-Host "Creating User Certificate as $($local:Subject)"
    Invoke-Expression ("& '$($local:MakeCert)' -n '$($local:Subject)' -a sha256 -len $KeySize -m 120 -cy end -sky exchange -eku '1.3.6.1.4.1.311.10.3.4,1.3.6.1.5.5.7.3.4,1.3.6.1.5.5.7.3.2' -iv '$OutputDirectory\$($local:Issuer).pvk' -ic '$OutputDirectory\$($local:Issuer).cer' -sv '$OutputDirectory\$($local:Name).pvk' '$OutputDirectory\$($local:Name).cer'")
    Invoke-Expression ("& '$($local:CertUtil)' -encode '$OutputDirectory\$($local:Name).cer' '$OutputDirectory\$($local:Name).pem'")
    Invoke-Expression ("& '$($local:Pvk2Pfx)' -pvk '$OutputDirectory\$($local:Name).pvk' -spc '$OutputDirectory\$($local:Name).cer' -pfx '$OutputDirectory\$($local:Name).pfx' -pi $($local:Password)")

    $local:Issuer = "IntermediateCA"
    Write-Host "The IP address of your host is necessary to define the SSL Certificate subject name"
    $local:Name = Read-Host "IPAddress"
    $local:Subject = "CN=$($local:Name),$SubjectBaseDn"
    Write-Host "Creating User Certificate as $($local:Subject)"
    Invoke-Expression ("& '$($local:MakeCert)' -n '$($local:Subject)' -a sha256 -len $KeySize -m 120 -cy end -sky exchange -eku '1.3.6.1.5.5.7.3.1' -iv '$OutputDirectory\$($local:Issuer).pvk' -ic '$OutputDirectory\$($local:Issuer).cer' -sv '$OutputDirectory\$($local:Name).pvk' '$OutputDirectory\$($local:Name).cer'")
    Invoke-Expression ("& '$($local:CertUtil)' -encode '$OutputDirectory\$($local:Name).cer' '$OutputDirectory\$($local:Name).pem'")
    Invoke-Expression ("& '$($local:Pvk2Pfx)' -pvk '$OutputDirectory\$($local:Name).pvk' -spc '$OutputDirectory\$($local:Name).cer' -pfx '$OutputDirectory\$($local:Name).pfx' -pi $($local:Password)")

    Write-Host -ForegroundColor Yellow "You now have four certificates in $OutputDirectory."
    Write-Host -ForegroundColor Green "To setup Safeguard SSL:"
    Write-Host "- Upload both RootCA and IntermediateCA to Safeguard using Install-SafeguardTrustedCertificate cmdlet"
    Write-Host "- Upload the certificate with the IP address to Safeguard using Install-SafeguardSSlCertificate cmdlet"
    Write-Host "- Import RootCA into your trusted root store using 'Run -> certmgr.msc'"
    Write-Host "- Import IntermediateCA into your intermediate store using 'Run -> certmgr.msc'"
    Write-Host "- Then, open a browser to Safeguard... if the IP address matches the subject you gave it should work"
    Write-Host -ForegroundColor Green "To setup client certificate user login:"
    Write-Host "- Upload both RootCA and IntermediateCA if you haven't already using Install-SafeguardTrustedCertificate cmdlet"
    Write-Host "- Import UserCert into your personal user store"
    Write-Host "- Create a user with the PrimaryAuthenticationProvider.Identity set to the thumbprint of UserCert"
    Write-Host "   - You can see your installed certificate thumbprints with: gci Cert:\CurrentUser\My\"
    Write-Host "   - The POST to create the user will need a body like this: -Body @{`n" `
    "                `"PrimaryAuthenticationProvider`" = @{ `"Id`" = -2; `"Identity`" = `"<thumbprint>`" };`n" `
    "                `"Name`" = `"CertBoy`";`n }"
    Write-Host "- Test it by getting a token: Connect-Safeguard -Thumbprint `"<thumbprint>`""
}

<#
.SYNOPSIS
Create an administered certificate signing request in Safeguard via the Web API.

.DESCRIPTION
Safeguard can generate administered certificate signing requests (CSRs) so that private keys never
leave the system.

This cmdlet creates new CSRs.  Stale CSRs can be deleted via Delete-SafeguardAdministeredCertificateSigningRequest.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Subject
A string containing the distinguished name of the subject of the CSR.

.PARAMETER KeyLength
An integer containing the key length (1024, 2048, 4096, default: 2048).

.PARAMETER IpAddresses
An array of strings containing IP addresses to use in subject alternative names.

.PARAMETER DnsNames
An array of strings containing DNS names to use in subject alternative names.

.PARAMETER CertificateAuthority
Request that the certificate should have the certificate authority attribute (default: false).

.PARAMETER KeyUsageCritical
Request that the certificate should designate the key usage as critical (default: false).

.PARAMETER ExtendedKeyUsageCritical
Request that the certificate should designate the extended key usage as critical (default: false).

.PARAMETER KeyUsages
An array of strings containing the key usages (CertificateSigning, KeyAgreement, KeyEncipherment, NonRepudiation, DigitalSignature).

.PARAMETER ExtendedKeyUsages
An array of strings containing the extended key usages (ServerAuthentication, ClientAuthentication, CodeSigning, SmartCard, TimeStamping).

.PARAMETER Notes
Additional notes for the CSR.

.PARAMETER OutFile
A string containing the path where the CSR file will be saved on the local appliance.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAdministeredCertificateSigningRequest -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
New-SafeguardAdministeredCertificateSigningRequest "CN=Safeguard,O=OneIdentity" -DnsNames "safeguard.oneidentity.com" -IpAddresses "10.10.10.10" -KeyUsageCritical -ExtendedKeyUsageCritical -KeyUsages @("KeyAgreement","KeyEncipherment","DigitalSignature") -ExtendedKeyUsages @("ClientAuthentication")
#>
function New-SafeguardAdministeredCertificateSigningRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$Subject,
        [Parameter(Mandatory=$false)]
        [ValidateSet(1024, 2048, 3072, 4096)]
        [int]$KeyLength = 2048,
        [Parameter(Mandatory=$false)]
        [string[]]$IpAddresses = $null,
        [Parameter(Mandatory=$false)]
        [string[]]$DnsNames = $null,
        [Parameter(Mandatory=$false)]
        [switch]$CertificateAuthority,
        [Parameter(Mandatory=$false)]
        [switch]$KeyUsageCritical,
        [Parameter(Mandatory=$false)]
        [switch]$ExtendedKeyUsageCritical,
        [Parameter(Mandatory=$false)]
        [ValidateSet('CertificateSigning', 'KeyAgreement', 'KeyEncipherment', 'NonRepudiation', 'DigitalSignature')]
        [string[]]$KeyUsages,
        [Parameter(Mandatory=$false)]
        [ValidateSet('ServerAuthentication', 'ClientAuthentication', 'CodeSigning', 'SmartCard', 'TimeStamping')]
        [string[]]$ExtendedKeyUsages,
        [Parameter(Mandatory=$false)]
        [string]$Notes,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$OutFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{
        CsrDetails = @{
            Subject = $Subject;
            KeyLength = $KeyLength;
        }
    }

    if ($PSBoundParameters.ContainsKey("IpAddresses"))
    {
        Import-Module -Name "$PSScriptRoot\ps-utilities.psm1" -Scope Local
        $IpAddresses | ForEach-Object {
            if (-not (Test-IpAddress $_))
            {
                throw "$_ is not an IP address"
            }
        }
        $local:Body.CsrDetails.IpAddresses = $IpAddresses
    }
    if ($PSBoundParameters.ContainsKey("Notes")) { $local:Body.Notes = $Notes }
    if ($PSBoundParameters.ContainsKey("DnsNames")) { $local:Body.CsrDetails.DnsNames = $DnsNames }
    if ($PSBoundParameters.ContainsKey("KeyUsages")) { $local:Body.CsrDetails.KeyUsages = $KeyUsages }
    if ($PSBoundParameters.ContainsKey("ExtendedKeyUsages")) { $local:Body.CsrDetails.ExtendedKeyUsages = $ExtendedKeyUsages }
    if ($PSBoundParameters.ContainsKey("CertificateAuthority")) { $local:Body.CsrDetails.CertificateAuthority = $true }
    if ($PSBoundParameters.ContainsKey("KeyUsageCritical")) { $local:Body.CsrDetails.KeyUsageCritical = $true }
    if ($PSBoundParameters.ContainsKey("ExtendedKeyUsageCritical")) { $local:Body.CsrDetails.ExtendedKeyUsageCritical = $true }

    $local:Csr = (Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Me/Certificates/Csr" -Body $local:Body)
    $local:Csr
    $local:Csr.Base64RequestData | Out-File -Encoding ASCII -FilePath $OutFile -NoNewline
    Write-Host "CSR saved to '$OutFile'"
}

<#
.SYNOPSIS
Get an administered certificate signing requests that have been generated for Safeguard via the Web API.

.DESCRIPTION
Safeguard can generate administered certificate signing requests (CSRs) so that private keys never
leave the system.

This cmdlet gets administered certificate CSRs that are currently outstanding but that have not yet been signed and
returned to Safeguard.  Stale CSRs can be deleted via Delete-SafeguardAdministeredCertificateSigningRequest.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CsrId
An integer containing an ID.

.PARAMETER Subject
A string containing the subject of a specific CSR.

.PARAMETER Fields
An array of the asset property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAdministeredCertificateSigningRequest -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardAdministeredCertificateSigningRequest "CN=Safeguard,O=OneIdentity"
#>
function Get-SafeguardAdministeredCertificateSigningRequest
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [int]$CsrId,
        [Parameter(Mandatory=$false)]
        [string]$Subject,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($Subject)
    {
        $local:Parameters = @{ filter = "Subject ieq '$Subject'" }
    }

    if ($PSBoundParameters.ContainsKey("CsrId"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/Certificates/Csr/$($CsrId)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/Certificates/Csr" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Edit an existing administered certificate signing request in Safeguard via the Web API.

.DESCRIPTION
Safeguard can generate administered certificate signing requests (CSRs) so that private keys never
leave the system.

This cmdlet edits the notes of an administered certificate CSRs that are currently outstanding but that have not yet been signed and
returned to Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CsrId
An integer containing an ID.

.PARAMETER Notes
A string containing the notes for the administered certificate CSR.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAdministeredCertificateSigningRequest -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Edit-SafeguardAdministeredCertificateSigningRequest 4 -Notes "New CSR for the lab server"
#>
function Edit-SafeguardAdministeredCertificateSigningRequest
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CsrId,
        [Parameter(Mandatory=$false)]
        [string]$Notes
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{
        Id = $CsrId;
    }

    if ($PSBoundParameters.ContainsKey("Notes"))
    {
        $local:Body.Notes = $Notes
    }
    else
    {
        # If there are no notes then there is nothing to update.
        return
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Me/Certificates/Csr/$($CsrId)" -Body $local:Body
}

<#
.SYNOPSIS
Delete an administered certificate signing request that has been generated for Safeguard via the Web API.

.DESCRIPTION
Safeguard can generate certificate signing requests (CSRs) so that private keys never
leave the system.

This cmdlet may be used to delete stale CSRs that have not yet been signed and will never be
returned to Safeguard.  You can find stale CSRs using Get-SafeguardAdministeredCertificateSigningRequest.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CsrId
An integer containing an ID.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAdministeredCertificateSigningRequest 4
#>
function Remove-SafeguardAdministeredCertificateSigningRequest
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CsrId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Me/Certificates/Csr/$($CsrId)"
}

<#
.SYNOPSIS
Create an administered certificate in Safeguard via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet upload a certificate so that it can be stored and shared with other Safeguard users. If
the certificate was signed from a CSR that was generated by Safeguard, the uploaded certifidate will
be matched and stored with the private key that was generated when the CSR was created.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER Notes
A string containing the notes for the administered certificate.

.PARAMETER NotifyDaysBefore
A integer that specifies the number of days before the certificate expires that Safeguard
should start notifying the administered certificate owners.

.PARAMETER NotifyDaysAfter
A integer that specifies the number of days after the certificate expires that Safeguard
should continue notifying the administered certificate owners.

.PARAMETER NotifyDaysAfter
A string containing the notes for the administered certificate CSR.

.PARAMETER PrivateKeyShareable
Indicates that the private key can be included when the certificate is downloaded.

.PARAMETER PassphraseRequired
Indicates that a passphrase must be provided by the caller when the certificate is downloaded.

.PARAMETER CertificateFile
A string containing the path to a certificate in DER or Base64 format.

.PARAMETER Password
A secure string to be used as a passphrase for the certificate PFX or P12 file.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAdministeredCertificateSigningRequest -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
New-SafeguardAdministeredCertificate -CertificateFile "c:\cert.pfx" -Password (ConvertTo-SecureString -AsPlainText "TestPassword" -Force)
#>
function New-SafeguardAdministeredCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false,Position=1)]
        [SecureString]$Password,
        [Parameter(Mandatory=$false)]
        [string]$Notes,
        [Parameter(Mandatory=$false)]
        [int]$NotifyDaysBefore = 30,
        [Parameter(Mandatory=$false)]
        [int]$NotifyDaysAfter = 30,
        [Parameter(Mandatory=$false)]
        [switch]$PrivateKeyShareable,
        [Parameter(Mandatory=$false)]
        [switch]$PassphraseRequired
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:CertificateContents = (Get-CertificateFileContents $CertificateFile)
    if (-not $CertificateContents)
    {
        throw "No valid certificate to upload"
    }

    if (-not $Password)
    {
        Write-Host "For no password just press enter..."
        $Password = (Read-host "Password" -AsSecureString)
    }
    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password

    $local:Body = @{
        Base64CertificateData = "$($local:CertificateContents)";
        Passphrase = "$($local:PasswordPlainText)";
        NotifyDaysBefore = $NotifyDaysBefore;
        NotifyDaysAfter = $NotifyDaysAfter;
    }

    if ($PSBoundParameters.ContainsKey("Notes")) { $local:Body.Notes = $Notes }
    if ($PSBoundParameters.ContainsKey("PrivateKeyShareable")) { $local:Body.IsPrivateKeyShareable = $true }
    if ($PSBoundParameters.ContainsKey("PassphraseRequired")) { $local:Body.IsPassphraseRequired = $true }

    Write-Host "Uploading Certificate..."
    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Me/Certificates" -Body $local:Body
}

<#
.SYNOPSIS
Get an administered certificate via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet gets an existing administered certificate that has been stored in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate. If the certificate Id is specifed, -Subject and -Thumbprint will be ignored.

.PARAMETER Subject
A string containing the subject of a specific administered certificate. Cannot be used if -Thumbprint is specified.

.PARAMETER Thumbprint
A string containing the thumbprint of a specific adminstered certificate. Cannot be used if -Subject is specified.

.PARAMETER Fields
An array of the asset property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAdministeredCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardAdministeredCertificate -Subject "CN=Safeguard,O=OneIdentity"

.EXAMPLE
Get-SafeguardAdministeredCertificate -Thumbprint 3E1A99AE7ACFB163DEE3CCAC00A437D675937FCA
#>
function Get-SafeguardAdministeredCertificate
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$false,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$false)]
        [string]$Subject,
        [Parameter(Mandatory=$false)]
        [string]$Thumbprint,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("CertificateId"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/Certificates/$($CertificateId)" -Parameters $local:Parameters
    }
    else
    {
        if ($PSBoundParameters.ContainsKey("Subject") -and $PSBoundParameters.ContainsKey("Thumbprint"))
        {
            throw "-Subject and -Thumbprint cannot be used in the same command."
        }

        if ($Subject)
        {
            $local:Parameters = @{ filter = "Subject ieq '$Subject'" }
        }

        if ($Thumbprint)
        {
            $local:Parameters = @{ filter = "CertificateDetails.Thumbprint eq '$Thumbprint'" }
        }

        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/Certificates" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Edit an existing administered certificate via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet edits an existing administered certificate that has been stored in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate.

.PARAMETER Notes
A string containing the notes for the administered certificate.

.PARAMETER NotifyDaysBefore
A integer that specifies the number of days before the certificate expires that Safeguard
should start notifying the administered certificate owners.

.PARAMETER NotifyDaysAfter
A integer that specifies the number of days after the certificate expires that Safeguard
should continue notifying the administered certificate owners.

.PARAMETER NotifyDaysAfter
A string containing the notes for the administered certificate CSR.

.PARAMETER PrivateKeyShareable
Indicates that the private key can be included when the certificate is downloaded.

.PARAMETER PassphraseRequired
Indicates that a passphrase must be provided by the caller when the certificate is downloaded.

.PARAMETER CertificateFile
A string containing the path to a certificate in DER or Base64 format.

.PARAMETER Password
A secure string to be used as a passphrase for the certificate PFX or P12 file.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAdministeredCertificate -AccessToken $token -Appliance 10.5.32.54 -Insecure

.EXAMPLE
Edit-SafeguardAdministeredCertificate 4 -Notes "Updated with a new certificate" -CertificateFile "c:\cert2.pfx"
#>
function Edit-SafeguardAdministeredCertificate
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$false)]
        [string]$Notes,
        [Parameter(Mandatory=$false)]
        [int]$NotifyDaysBefore,
        [Parameter(Mandatory=$false)]
        [int]$NotifyDaysAfter,
        [Parameter(Mandatory=$false)]
        [switch]$PrivateKeyShareable,
        [Parameter(Mandatory=$false)]
        [switch]$PassphraseRequired,
        [Parameter(Mandatory=$false)]
        [string]$CertificateFile,
        [Parameter(Mandatory=$false)]
        [SecureString]$Password
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:Body = @{
        Id = $CertificateId;
    }

    if ($PSBoundParameters.ContainsKey("CertificateFile"))
    {
        $local:CertificateContents = (Get-CertificateFileContents $CertificateFile)
        if (-not $CertificateContents)
        {
            throw "No valid certificate to upload"
        }

        if (-not $Password)
        {
            Write-Host "For no password just press enter..."
            $Password = (Read-host "Password" -AsSecureString)
        }
        $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password

        $local:Body.Base64CertificateData = "$($local:CertificateContents)";
        $local:Body.Passphrase = "$($local:PasswordPlainText)";
    }

    if ($PSBoundParameters.ContainsKey("Notes")) { $local:Body.Notes = $Notes }
    if ($PSBoundParameters.ContainsKey("PrivateKeyShareable")) { $local:Body.IsPrivateKeyShareable = $true }
    if ($PSBoundParameters.ContainsKey("PassphraseRequired")) { $local:Body.IsPassphraseRequired = $true }
    if ($PSBoundParameters.ContainsKey("NotifyDaysBefore")) { $local:Body.NotifyDaysBefore = $NotifyDaysBefore }
    if ($PSBoundParameters.ContainsKey("NotifyDaysAfter")) { $local:Body.NotifyDaysAfter = $NotifyDaysAfter }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Me/Certificates/$($CertificateId)" -Body $local:Body
}

<#
.SYNOPSIS
Delete an administered certificate via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet deletes an existing administered certificate that has been stored in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Remove-SafeguardAdministeredCertificate 4
#>
function Remove-SafeguardAdministeredCertificate
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [string]$CertificateId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core DELETE "Me/Certificates/$($CertificateId)"
}

<#
.SYNOPSIS
Create an administered certificate share via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates. The adminstered certificates can be shared
with other Safeguard users or user groups.

This cmdlet creates a new administered certificate share with a share expiration date.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate.

.PARAMETER UserId
An integer containing the ID of a Safeguard user with whom the certificate should be shared.

.PARAMETER GroupId
An integer containing the ID of a Safeguard user group with whom the certificate should be shared.

.PARAMETER ExpirationDate
A DateTime containing the UTC date/time when the share expires.  For example: "2024-10-17T12:11:12Z".

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
New-SafeguardAdministeredCertificateShare -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
New-SafeguardAdministeredCertificateShare -CertificateId 4 -UserId 12 -ExpirationDate 2024-10-17T12:11:12Z

.EXAMPLE
New-SafeguardAdministeredCertificateShare -CertificateId 4 -GroupId 5
#>
function New-SafeguardAdministeredCertificateShare
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$false)]
        [int]$UserId,
        [Parameter(Mandatory=$false)]
        [int]$GroupId,
        [Parameter(Mandatory=$false)]
        [DateTime]$ExpirationDate
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("UserId") -and $PSBoundParameters.ContainsKey("GroupId"))
    {
        throw "-UserId and -GroupId cannot be used in the same command."
    }

    if (!$PSBoundParameters.ContainsKey("UserId") -and !$PSBoundParameters.ContainsKey("GroupId"))
    {
        throw "Either -UserId or -GroupId must be specified."
    }

    $local:Body = @{
        AdministeredCertificateId = $CertificateId;
    }

    if ($PSBoundParameters.ContainsKey("UserId"))
    {
        $local:Body.SharedWithId = $UserId
        $local:Body.ShareType = "User"
    }

    if ($PSBoundParameters.ContainsKey("GroupId"))
    {
        $local:Body.SharedWithId = $GroupId
        $local:Body.ShareType = "Group"
    }

    if ($PSBoundParameters.ContainsKey("ExpirationDate")) { $local:Body.SharedExpirationDate = $ExpirationDate }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core POST "Me/Certificates/$($CertificateId)/Share" -Body $local:Body
}

<#
.SYNOPSIS
Get an administered certificate share via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet edits an existing administered certificate share that has been stored in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate.

.PARAMETER UserId
An integer containing the ID of a Safeguard user with whom the certificate should be shared.

.PARAMETER GroupId
An integer containing the ID of a Safeguard user group with whom the certificate should be shared.

.PARAMETER Fields
An array of the asset property names to return.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAdministeredCertificateShare -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardAdministeredCertificateShare -CertificateId 4 -GroupId 5
#>
function Get-SafeguardAdministeredCertificateShare
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$false)]
        [int]$UserId,
        [Parameter(Mandatory=$false)]
        [int]$GroupId,
        [Parameter(Mandatory=$false)]
        [string[]]$Fields
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("UserId") -and $PSBoundParameters.ContainsKey("GroupId"))
    {
        throw "-UserId and -GroupId cannot be used in the same command."
    }

    $local:Parameters = $null
    if ($Fields)
    {
        $local:Parameters = @{ fields = ($Fields -join ",")}
    }

    if ($PSBoundParameters.ContainsKey("UserId"))
    {
        $local:ShareType = "User"
        $local:ShareWithId = $UserId
    }

    if ($PSBoundParameters.ContainsKey("GroupId"))
    {
        $local:ShareType = "Group"
        $local:ShareWithId = $GroupId
    }

    if ($local:ShareType)
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/Certificates/$($CertificateId)/Share/$($local:ShareWithId)?type=$($local:ShareType)" -Parameters $local:Parameters
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/Certificates/$($CertificateId)/Share" -Parameters $local:Parameters
    }
}

<#
.SYNOPSIS
Edit an existing administered certificate share via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet edits an existing administered certificate share that has been stored in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate.

.PARAMETER UserId
An integer containing the ID of a Safeguard user with whom the certificate should be shared.

.PARAMETER GroupId
An integer containing the ID of a Safeguard user group with whom the certificate should be shared.

.PARAMETER ExpirationDate
A DateTime containing the UTC date/time when the share expires.  For example: "2024-10-17T12:11:12Z".

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAdministeredCertificateShare -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Edit-SafeguardAdministeredCertificateShare -CertificateId 4 -UserId 12 -ExpirationDate 2024-10-17T12:11:12Z

.EXAMPLE
Edit-SafeguardAdministeredCertificateShare -CertificateId 4 -GroupId 5
#>
function Edit-SafeguardAdministeredCertificateShare
{
    [CmdletBinding(DefaultParameterSetName="Attributes")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$false)]
        [int]$UserId,
        [Parameter(Mandatory=$false)]
        [int]$GroupId,
        [Parameter(Mandatory=$false)]
        [DateTime]$ExpirationDate
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("UserId") -and $PSBoundParameters.ContainsKey("GroupId"))
    {
        throw "-UserId and -GroupId cannot be used in the same command."
    }

    if (!$PSBoundParameters.ContainsKey("UserId") -and !$PSBoundParameters.ContainsKey("GroupId"))
    {
        throw "Either -UserId or -GroupId must be specified."
    }

    $local:Body = @{
        AdministeredCertificateId = $CertificateId;
    }

    if ($PSBoundParameters.ContainsKey("UserId"))
    {
        $local:Body.SharedWithId = $UserId
        $local:Body.ShareType = "User"
        $local:ShareWithId = $UserId
    }

    if ($PSBoundParameters.ContainsKey("GroupId"))
    {
        $local:Body.SharedWithId = $GroupId
        $local:Body.ShareType = "Group"
        $local:ShareWithId = $GroupId
    }

    if ($PSBoundParameters.ContainsKey("ExpirationDate")) { $local:Body.ShareExpirationDate = $ExpirationDate }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core PUT "Me/Certificates/$($CertificateId)/Share/$($local:ShareWithId)" -Body $local:Body
}

<#
.SYNOPSIS
Delete an administered certificate share via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet deletes an existing administered certificate share that has been stored in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate.

.PARAMETER UserId
An integer containing the ID of a Safeguard user with whom the certificate should be shared.

.PARAMETER GroupId
An integer containing the ID of a Safeguard user group with whom the certificate should be shared.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Edit-SafeguardAdministeredCertificateShare -CertificateId 4 -GroupId 5
#>
function Remove-SafeguardAdministeredCertificateShare
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$false)]
        [int]$UserId,
        [Parameter(Mandatory=$false)]
        [int]$GroupId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if ($PSBoundParameters.ContainsKey("UserId") -and $PSBoundParameters.ContainsKey("GroupId"))
    {
        throw "-UserId and -GroupId cannot be used in the same command."
    }

    if (!$PSBoundParameters.ContainsKey("UserId") -and !$PSBoundParameters.ContainsKey("GroupId"))
    {
        throw "Either -UserId or -GroupId must be specified."
    }

    if ($PSBoundParameters.ContainsKey("UserId"))
    {
        $local:ShareType = "User"
        $local:ShareWithId = $UserId
    }

    if ($PSBoundParameters.ContainsKey("GroupId"))
    {
        $local:ShareType = "Group"
        $local:ShareWithId = $GroupId
    }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        DELETE "Me/Certificates/$($CertificateId)/Share/$($local:ShareWithId)?type=$($local:ShareType)"
}

<#
.SYNOPSIS
Download an administered certificate via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet downloads an existing administered certificate that is either owned by or shared with a Safeguard user.
If the parameters -Password or -IncludePrivateKey are included in the command, the certificate will be downloaded in
PKCS12 (PFX) format.  Otherwise, the certificate will be downloaded in X509 format.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate. If the certificate Id is specifed, -Subject and -Thumbprint will be ignored.

.PARAMETER IncludePrivateKey
Include the private key in the downloaded certificate if available.

.PARAMETER Password
A secure string to be applied as a passphrase for the downloaded certificate PFX or P12 file.

.PARAMETER OutFile
A string containing the path where the downloaded certificate file will be saved on the local appliance.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Save-SafeguardAdministeredCertificate -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Save-SafeguardAdministeredCertificate -CertificateId 5

#>
function Save-SafeguardAdministeredCertificate
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$OutFile,
        [Parameter(Mandatory=$false)]
        [SecureString]$Password,
        [Parameter(Mandatory=$false)]
        [switch]$IncludePrivateKey
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    if (-not $Password)
    {
        Write-Host "For no password just press enter..."
        $Password = (Read-host "Password" -AsSecureString)
    }
    $local:PasswordPlainText = [System.Net.NetworkCredential]::new("", $Password).Password

    $local:Body = @{  }

    if ($local:PasswordPlainText) { $local:Body.PassPhrase = "$($local:PasswordPlainText)" }
    if ($PSBoundParameters.ContainsKey("IncludePrivateKey")) { $local:Body.IncludePrivateKey = $true }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        POST "Me/Certificates/$($CertificateId)/Download" -Body $local:Body -Parameters $local:Parameters -OutFile $OutFile
    Write-Host "Certificate saved to '$OutFile'"
}

<#
.SYNOPSIS
Get the history of an administered certificate via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet gets the history for an existing administered certificate that has been stored in Safeguard.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate.

.PARAMETER Days
Number of days of data to retrieve.

.PARAMETER EventId
The event id for the administered certificate event.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAdministeredCertificateHistory -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Get-SafeguardAdministeredCertificateHistory 12 -Days 5

.EXAMPLE
Get-SafeguardAdministeredCertificateHistory 12 -EventId 638422571883650000

#>
function Get-SafeguardAdministeredCertificateHistory
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$false)]
        [int]$Days = 30,
        [Parameter(Mandatory=$false)]
        [long]$EventId
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    $local:PastDays = (0 - $Days)
    $LocalDate = (Get-Date).AddDays($local:PastDays)
    $local:DayOnly = (New-Object "System.DateTime" -ArgumentList $LocalDate.Year, $LocalDate.Month, $LocalDate.Day)

    if ($PSBoundParameters.ContainsKey("Days") -and $PSBoundParameters.ContainsKey("EventId"))
    {
        throw "-Days and -EventId cannot be used in the same command."
    }

    if ($PSBoundParameters.ContainsKey("EventId"))
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/Certificates/$($CertificateId)/CertificateHistory/$($EventId)"
    }
    else
    {
        Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
            GET "Me/Certificates/$($CertificateId)/CertificateHistory" -Parameters @{ startDate = (Format-DateTimeAsString $local:DayOnly) }
    }

}

<#
.SYNOPSIS
Download an administered certificate from a history event via the Web API.

.DESCRIPTION
Safeguard can store and share administered certificates.

This cmdlet downloads a certificate from an existing administered certificate history event.
The certificate will be downloaded in PKCS12 (PFX) format.

.PARAMETER Appliance
IP address or hostname of a Safeguard appliance.

.PARAMETER AccessToken
A string containing the bearer token to be used with Safeguard Web API.

.PARAMETER Insecure
Ignore verification of Safeguard appliance SSL certificate.

.PARAMETER CertificateId
An integer containing the ID of the administered certificate.

.PARAMETER EventId
The event id for the administered certificate event.

.PARAMETER OutFile
A string containing the path where the downloaded certificate file will be saved on the local appliance.

.INPUTS
None.

.OUTPUTS
JSON response from Safeguard Web API.

.EXAMPLE
Get-SafeguardAdministeredCertificateHistory -AccessToken $token -Appliance 10.5.32.54

.EXAMPLE
Save-SafeguardAdministeredCertificateHistory -CertificateId 5 -EventId 638422571883650000 -OutFile c:\oldcert.pfx

#>
function Save-SafeguardAdministeredCertificateHistory
{
    [CmdletBinding(DefaultParameterSetName="None")]
    Param(
        [Parameter(Mandatory=$false)]
        [string]$Appliance,
        [Parameter(Mandatory=$false)]
        [object]$AccessToken,
        [Parameter(Mandatory=$false)]
        [switch]$Insecure,
        [Parameter(Mandatory=$true,Position=0)]
        [int]$CertificateId,
        [Parameter(Mandatory=$true,Position=1)]
        [long]$EventId,
        [Parameter(Mandatory=$true,Position=2)]
        [string]$OutFile
    )

    if (-not $PSBoundParameters.ContainsKey("ErrorAction")) { $ErrorActionPreference = "Stop" }
    if (-not $PSBoundParameters.ContainsKey("Verbose")) { $VerbosePreference = $PSCmdlet.GetVariableValue("VerbosePreference") }

    Invoke-SafeguardMethod -AccessToken $AccessToken -Appliance $Appliance -Insecure:$Insecure Core `
        GET "Me/Certificates/$($CertificateId)/CertificateHistory/$($EventId)/Download" -OutFile $OutFile
    Write-Host "Historical certificate saved to '$OutFile'"
}
