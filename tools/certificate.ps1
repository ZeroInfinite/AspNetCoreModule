# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for full license information.

##############################################################################
# Example
# $thumbPrint = "914BA16B8E86E90C69BA72F16B60214232D22D20"
# $thumbPrint = .\certificate.ps1 -Command Create-SelfSignedCertificate -Subject localhost -TargetSSLStore "Cert:\LocalMachine\My"
# .\certificate.ps1 -Command Get-CertificatePublicKey -TargetThumbPrint $thumbPrint -TargetSSLStore "Cert:\LocalMachine\My"
# .\certificate.ps1 -Command Export-CertificateTo -TargetThumbPrint $thumbPrint -TargetSSLStore "Cert:\LocalMachine\My" -ExportToSSLStore "Cert:\LocalMachine\Root"
# .\certificate.ps1 -Command Export-CertificateTo -TargetThumbPrint $thumbPrint -TargetSSLStore "Cert:\LocalMachine\My" -ExportToSSLStore "Cert:\CurrentUser\My"
# .\certificate.ps1 -Command Delete-Certificate -TargetThumbPrint $thumbPrint 
# .\certificate.ps1 -Command Delete-Certificate -TargetThumbPrint $thumbPrint -TargetSSLStore "Cert:\LocalMachine\Root"
##############################################################################


Param(
    [parameter(Mandatory=$true , Position=0)]
    [ValidateSet("Create-SelfSignedCertificate",
                 "Delete-Certificate",
                 "Export-CertificateTo",
                 "Get-CertificatePublicKey")]
    [string]
    $Command,

    [parameter()]
    [string]
    $Subject,

    [Parameter()]
    [string]
    $FriendlyName = "", 

    [Parameter()]
    [string[]]
    $AlternativeNames = "",

    [Parameter()]
    [string]
    $TargetSSLStore = "",

    [Parameter()]
    [string]
    $ExportToSSLStore = "",
    
    [Parameter()]
    [string]
    $TargetThumbPrint = ""
)

# adjust parameter variable
if (-not $TargetSSLStore)
{
    $TargetSSLStore = "Cert:\LocalMachine\My"
}

if (-not $ExportToSSLStore)
{
    $ExportToSSLStore = "Cert:\LocalMachine\Root"
}

function Create-SelfSignedCertificate($_subject, $_friendlyName, $_alternativeNames) {

    if (-not $_subject)
    {
        return ("_subject is required")
    }

    $subjectDn = new-object -com "X509Enrollment.CX500DistinguishedName"
    $subjectDn.Encode( "CN=" + $_subject, $subjectDn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
    $issuer = $_subject
    $issuerDn = new-object -com "X509Enrollment.CX500DistinguishedName"
    $issuerDn.Encode("CN=" + $issuer, $subjectDn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)

    #
    # Create a new Private Key
    $key = new-object -com "X509Enrollment.CX509PrivateKey"
    $key.ProviderName =  "Microsoft Enhanced RSA and AES Cryptographic Provider"    
    # XCN_AT_SIGNATURE, The key can be used for signing
    $key.KeySpec = 2
    $key.Length = 2048
    # MachineContext 0: Current User, 1: Local Machine
    $key.MachineContext = 1
    $key.Create() 

    $cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $subjectDn
    $cert.Issuer = $issuerDn
    $cert.NotBefore = (get-date).AddMinutes(-10)
    $cert.NotAfter = $cert.NotBefore.AddYears(2)

    #Use Sha256
    $hashAlgorithm = New-Object -ComObject X509Enrollment.CObjectId
    $hashAlgorithm.InitializeFromAlgorithmName(1,0,0,"SHA256")
    $cert.HashAlgorithm = $hashAlgorithm    
	 
    #
    # Extended key usage
    $clientAuthOid = New-Object -ComObject "X509Enrollment.CObjectId"
    $clientAuthOid.InitializeFromValue("1.3.6.1.5.5.7.3.2")
    $serverAuthOid = new-object -com "X509Enrollment.CObjectId"
    $serverAuthOid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuOids = new-object -com "X509Enrollment.CObjectIds.1"
    $ekuOids.add($clientAuthOid)
    $ekuOids.add($serverAuthOid)
    $ekuExt = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
    $ekuExt.InitializeEncode($ekuOids)
    $cert.X509Extensions.Add($ekuext)
	
    #
    # Key usage
    $keyUsage = New-Object -com "X509Enrollment.cx509extensionkeyusage"
    # XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE
    $flags = 0x20
    # XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE
    $flags = $flags -bor 0x80
    $keyUsage.InitializeEncode($flags)
    $cert.X509Extensions.Add($keyUsage)

    #
    # Subject alternative names
    if ($_alternativeNames -ne $null) {
        $names =  new-object -com "X509Enrollment.CAlternativeNames"
        $altNames = new-object -com "X509Enrollment.CX509ExtensionAlternativeNames"
        foreach ($n in $_alternativeNames) {
            $name = new-object -com "X509Enrollment.CAlternativeName"
            # Dns Alternative Name
            $name.InitializeFromString(3, $n)
            $names.Add($name)
        }
        $altNames.InitializeEncode($names)
        $cert.X509Extensions.Add($altNames)
    }

    $cert.Encode()

    #$locator = $(New-Object "System.Guid").ToString()
    $locator = [guid]::NewGuid().ToString()
    $enrollment = new-object -com "X509Enrollment.CX509Enrollment"
    $enrollment.CertificateFriendlyName = $locator
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")

    # Wait for certificate to be populated
    $end = $(Get-Date).AddSeconds(1)
    do {
        $Certificates = Get-ChildItem Cert:\LocalMachine\My
        foreach ($item in $Certificates)
        {
            if ($item.FriendlyName -eq $locator)
            {
                $CACertificate = $item
            }
        }
    } while ($CACertificate -eq $null -and $(Get-Date) -lt $end)

    $thumbPrint = ""
    if ($CACertificate -and $CACertificate.Thumbprint)
    {
        $thumbPrint = $CACertificate.Thumbprint.Trim()
    }
    return $thumbPrint
}

function Delete-Certificate($_targetThumbPrint, $_targetSSLStore = $TargetSSLStore) {

    if (-not $_targetThumbPrint)
    {
        return ("_targetThumbPrint is required")
    }

    if (Test-Path "$_targetSSLStore\$_targetThumbPrint")
    {
        Remove-Item "$_targetSSLStore\$_targetThumbPrint" -Force -Confirm:$false
    }

    if (Test-Path "$_targetSSLStore\$_targetThumbPrint")
    {
        return ("Failed to delete a certificate of $_targetThumbPrint")
    }
}

function Export-CertificateTo($_targetThumbPrint)
{
    if (-not $_targetThumbPrint)
    {
        return ("_targetThumbPrint is required")
    }

    if (-not (Test-Path "$TargetSSLStore\$_targetThumbPrint"))
    {
        return ("Export failed. Can't find target certificate: $TargetSSLStore\$_targetThumbPrint")
    }

    Delete-Certificate $_targetThumbPrint $ExportToSSLStore
    if (Test-Path "$ExportToSSLStore\$_targetThumbPrint")
    {
        return ("Export failed. Can't delete already existing one $ExportToSSLStore\$_targetThumbPrint")
    }

    $cert = Get-Item "$TargetSSLStore\$_targetThumbPrint"
    $tempExportFile = "$env:temp\_tempCertificate.cer"
    if (Test-Path $tempExportFile)
    {
        Remove-Item $tempExportFile -Force -Confirm:$false
    }
                
    Export-Certificate -Cert $cert -FilePath $tempExportFile | Out-Null
    if (-not (Test-Path $tempExportFile))
    {
        return ("Export failed. Can't export $TargetSSLStore\$_targetThumbPrint to $tempExportFile")
    }

    Import-Certificate -CertStoreLocation $ExportToSSLStore -FilePath $tempExportFile | Out-Null    
    if (-not (Test-Path "$ExportToSSLStore\$_targetThumbPrint"))
    {
        return ("Export failed. Can't copy $TargetSSLStore\$_targetThumbPrint to $ExportToSSLStore")
    }
}

function Get-CertificatePublicKey($_targetThumbPrint)
{
    if (-not $_targetThumbPrint)
    {
        return ("_targetThumbPrint is required")
    }

    if (-not (Test-Path "$TargetSSLStore\$_targetThumbPrint"))
    {
        return ("Can't find target certificate")
    }

    $cert = Get-Item "$TargetSSLStore\$_targetThumbPrint"
    $byteArray = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $publicKey = [System.Convert]::ToBase64String($byteArray).Trim()

    return $publicKey
}

switch ($Command)
{
    "Create-SelfSignedCertificate"
    {
        return Create-SelfSignedCertificate $Subject $FriendlyName $AlternativeNames
    }
    "Delete-Certificate"
    {
        return Delete-Certificate $TargetThumbPrint
    }
    "Export-CertificateTo"
    {
        return Export-CertificateTo $TargetThumbPrint
    }
    "Get-CertificatePublicKey"
    {
        return Get-CertificatePublicKey $TargetThumbPrint
    }
    default
    {
        throw "Unknown command"
    }
}
