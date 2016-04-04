#requires -Version 3

function Get-SSLReport {
<#
.SYNOPSIS
    Query SSLLabs and generate a security report

.PARAMETER Hostname
    [String]
    
    -Hostname "www.letsencrypt.com"

.PARAMETER Publish
    [boolean]

    -Publish "$true|$false"

.PARAMETER startNew
    [boolean]

    -startNew "$true|$false"

.PARAMETER fromCache
    [boolean]

    -fromCache "$true|$false"

.PARAMETER maxAge
    [int]

    -maxAge "24" (hours)

.PARAMETER ignoreMismatch
    [boolean]

    -ignoreMismatch "$true|$false"

.PARAMETER showChain
    [boolean]

    -showChain "$true|$false"
      
.EXAMPLE
    Get-SSLReport -Hostname www.letsencrypt.com -Publish $true -startNew $true -ignoreMismatch $true
             
.EXAMPLE
    Get-SSLReport -Hostname www.letsencrypt.com -Publish $false -startNew $false -fromCache $true -maxAge 24 -ignoreMismatch $true -showChain $true
             
.NOTES
    Info      : Function to query SSLLabs
    Developer : Lukas Sassl
    Date      : 01.04.2016
    Version   : 0.1 (Beta)
#>
    
param(
    [parameter(Mandatory=$true,Position=0)][string]$Hostname, 
    [parameter(Mandatory=$true,Position=1)][boolean]$Publish,
    [parameter(Mandatory=$false,Position=2)][boolean]$startNew,
    [parameter(Mandatory=$false,Position=2)][boolean]$fromCache,
    [parameter(Mandatory=$false,Position=3)][int]$maxAge,
    [parameter(Mandatory=$false,Position=4)][boolean]$ignoreMismatch,
    [parameter(Mandatory=$false,Position=5)][boolean]$showChain
)

#Process checkpoint
$PROCESS_CHECKPOINT = $false

#API Call info
$SSLLabs_info = "https://api.ssllabs.com/api/v2/info"

#API Call analyze uri
$SSLLabs_analyze = "https://api.ssllabs.com/api/v2/analyze?"

#Test SSLLabs API availability
try {
    $Result = Invoke-RestMethod -Method Get -Uri $SSLLabs_info
    Write-Host "[INFO] SSLLabs API is available" -ForegroundColor Green
    Write-Host "[INFO] Current engine version:"$Result.engineVersion -ForegroundColor Green
    Write-Host "[INFO]"$Result.messages -ForegroundColor Green
    Write-Host "`n"
    $PROCESS_CHECKPOINT = $true
}
catch {
    $PROCESS_CHECKPOINT = $false
}

if($PROCESS_CHECKPOINT) {

    #Check parameters
    if($startNew) {
        $String_startNew = "on"

        if($fromCache) {
            Write-Host "[ERROR] It's not allowed to use 'startNew' together with 'fromCache'!" -ForegroundColor Red
            break
        }
        else {
            $String_fromCache = "off"
        }
    
    }
    else {
        $String_startNew = "off"
    }

    if($fromCache -eq $false) {
        $String_fromCache = "off"

        if($maxAge -gt 0) {
            Write-Host "[ERROR] It's not allowed to use the parameter 'maxAge' when 'fromCache' is set to 'false!" -ForegroundColor Red
            break
        }
    
    }
    else {
        $String_fromCache = "on"
    }

    if($ignoreMismatch) {
        $String_ignoreMismatch = "on"
        Write-Host "[INFO] Please note that the parameter 'ignoreMismatch' is ignored if a cached report is returned." -ForegroundColor Yellow
    }
    else {
        $String_ignoreMismatch = "off"
    }

    #Build final uri
    if($maxAge -gt 0) {
        $SSLLabs_analyze_final = $SSLLabs_analyze + "host=" + $Hostname + "&publish=" + $Publish + "&startNew=" + $String_startNew + "&fromCache=" + $String_fromCache + "&ignoreMismatch=" + $String_ignoreMismatch + "&maxAge=" + $maxAge + "&all=on"
    }
    else {
        $SSLLabs_analyze_final = $SSLLabs_analyze + "host=" + $Hostname + "&publish=" + $Publish + "&startNew=" + $String_startNew + "&fromCache=" + $String_fromCache + "&ignoreMismatch=" + $String_ignoreMismatch + "&all=on"
    }
    
    #Start WebRequest
    try {
        $SSLLabs_WebRequest_Json = Invoke-WebRequest -Uri $SSLLabs_analyze_final
    }
    catch {
        break
    }

    #Convert Json content
    try {
        $SSLLabs_WebRequest_Converted = ConvertFrom-Json -InputObject $SSLLabs_WebRequest_Json.content
    }
    catch {
        break
    }

    #Check request status
    $i = 0

    if($SSLLabs_WebRequest_Converted.status -notmatch "READY") {
        Write-Host "[INFO] Current status is: $($SSLLabs_WebRequest_Converted.status)" -ForegroundColor Yellow
        do {

            $i++

            Write-Host "[INFO] Your request is not yet finished. Please be patient..." -ForegroundColor Yellow
            $SSLLabs_WebRequest_Ready = $false
            Start-Sleep 60
            
            #Get WebRequest status and convert content
            $SSLLabs_analyze_temp = $SSLLabs_analyze + "host=" + $Hostname + "&publish=" + $Publish + "&startNew=off" + "&ignoreMismatch=" + $String_ignoreMismatch + "&all=on"
            try {
                $SSLLabs_WebRequest_Json_temp = Invoke-WebRequest -Uri $SSLLabs_analyze_temp
            }
            catch {
                break
            }

            try {
                $SSLLabs_WebRequest_Converted_temp = ConvertFrom-Json -InputObject $SSLLabs_WebRequest_Json_temp.content
            }
            catch {
                break
            }

            if(($SSLLabs_WebRequest_Converted_temp.status -match "READY") -and ($SSLLabs_WebRequest_Converted_temp.startTime -match $SSLLabs_WebRequest_Converted.startTime)) {
                $SSLLabs_WebRequest_Ready = $true
                $SSLLabs_WebRequest_Converted = $SSLLabs_WebRequest_Converted_temp
            }

        } 
        until (($SSLLabs_WebRequest_Ready -eq $true) -or ($i -eq 6))
    }
    else {
        $SSLLabs_WebRequest_Ready = $true
    }


    if($SSLLabs_WebRequest_Ready) {

        Write-Host "[SUCCESS] Request was successful after $i run(s)!" -ForegroundColor Green
        Write-Host "`n"

        ForEach($SSLLabs_Endpoint in $SSLLabs_WebRequest_Converted.endpoints) {

            Write-Host "[INFO] Test Results"
            Write-Host "[INFO] ------------------"
            Write-Host "[INFO]"
            if($SSLLabs_Endpoint.grade -like "A*") {
                Write-Host "[INFO] Grade:"$SSLLabs_Endpoint.grade -ForegroundColor Green
            }
            elseif(($SSLLabs_Endpoint.grade -like "B*") -or ($SSLLabs_Endpoint.grade -like "C*")) {
                Write-Host "[INFO] Grade:"$SSLLabs_Endpoint.grade -ForegroundColor Yellow
            }
            else {
                Write-Host "[INFO] Grade:"$SSLLabs_Endpoint.grade -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.hasWarnings -ne $true) {
                Write-Host "[INFO] Has Warnings:"$SSLLabs_Endpoint.hasWarnings -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Has Warnings:"$SSLLabs_Endpoint.hasWarnings -ForegroundColor Red
            }
            if($SSLLabs_WebRequest_Converted.status -match "READY") {
                Write-Host "[INFO] Status:"$SSLLabs_WebRequest_Converted.status -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Status:"$SSLLabs_WebRequest_Converted.status -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.progress -eq 100) {
                Write-Host "[INFO] Progress:"$SSLLabs_Endpoint.progress "%" -ForegroundColor Green
            }
            elseif($SSLLabs_Endpoint.progress -eq -1) {
                Write-Host "[INFO] Progress: Unable to connect to the server. Check hostname or try again later!" -ForegroundColor Red
                break
            }
            else {
                Write-Host "[INFO] Progress:"$SSLLabs_Endpoint.progress "%" -ForegroundColor Red
            }
            Write-Host "[INFO] Public:"$SSLLabs_WebRequest_Converted.isPublic

            Write-Host "`n"
            Write-Host "[INFO] Server Information"
            Write-Host "[INFO] ------------------"
            Write-Host "[INFO]"
            Write-Host "[INFO] Host:"$SSLLabs_WebRequest_Converted.host
            Write-Host "[INFO] IP Address:"$SSLLabs_Endpoint.ipAddress
            Write-Host "[INFO] Server Hostname:"$SSLLabs_Endpoint.serverName
            Write-Host "[INFO] HTTP Server Signature:"$SSLLabsEndpoint.details.serverSignature

            Write-Host "`n"
            Write-Host "[INFO] Certificate"
            Write-Host "[INFO] ------------------"
            Write-Host "[INFO]"
            Write-Host "[INFO] Subject:"$SSLLabs_Endpoint.details.cert.subject
            Write-Host "[INFO] Fingerprint SHA1:"$SSLLabs_Endpoint.details.cert.sha1Hash
            Write-Host "[INFO] Pin SHA256:"$SSLLabs_Endpoint.details.cert.pinSha256
            Write-Host "[INFO] Common Names:"$SSLLabs_Endpoint.details.cert.commonNames
            Write-Host "[INFO] Alternative Names:"$SSLLabs_Endpoint.details.cert.altNames
            Write-Host "[INFO] Key Algorithm:"$SSLLabs_Endpoint.details.key.alg
            if($SSLLabs_Endpoint.details.key.size -ge 2048) {
                Write-Host "[INFO] Key Size:"$SSLLabs_Endpoint.details.key.size -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Key Size:"$SSLLabs_Endpoint.details.key.size -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.key.strength -ge 2048) {
                Write-Host "[INFO] Key Strength:"$SSLLabs_Endpoint.details.key.strength -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Key Strength:"$SSLLabs_Endpoint.details.key.strength -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.key.debianFlaw -eq $false) {
                Write-Host "[INFO] Weak Key (Debian):"$SSLLabs_Endpoint.details.key.debianFlaw -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Weak Key (Debian):"$SSLLabs_Endpoint.details.key.debianFlaw -ForegroundColor Red
            }
            Write-Host "[INFO] Issuer:"$SSLLabs_Endpoint.details.cert.issuerLabel
            Write-Host "[INFO] Signature Algorithm:"$SSLLabs_Endpoint.details.cert.sigAlg
            if($SSLLabs_Endpoint.details.cert.validationType -match "E") {
                Write-Host "[INFO] Extended Validation: True" -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Extended Validation: False" -ForegroundColor Gray
            }
            ForEach($crlURI in $SSLLabs_Endpoints.details.cert.crlURIs) {
                Write-Host "[INFO] CRL:"$crlURI -ForegroundColor Gray
            }
            ForEach($ocspURI in $SSLLabs_Endpoint.details.cert.ocspURIs) {
                Write-Host "[INFO] OCSP:"$ocspURI -ForegroundColor Gray
            }
            if($SSLLabs_Endpoint.details.cert.revocationStatus -eq 0) {
                Write-Host "[INFO] Revocation Status: Not checked" -ForegroundColor Gray
            }
            elseif($SSLLabs_Endpoint.details.cert.revocationStatus -eq 1) {
                Write-Host "[INFO] Revocation Status: Bad (certificate revoked)" -ForegroundColor Red
            }
            elseif($SSLLabs_Endpoint.details.cert.revocationStatus -eq 2) {
                Write-Host "[INFO] Revocation Status: Good (not revoked)" -ForegroundColor Green
            }
            elseif($SSLLabs_Endpoint.details.cert.revocationStatus -eq 3) {
                Write-Host "[INFO] Revocation Status: Revocation check error" -ForegroundColor Red
            }
            elseif($SSLLabs_Endpoint.details.cert.revocationStatus -eq 4) {
                Write-Host "[INFO] Revocation Status: No revocation information" -ForegroundColor Gray
            }
            elseif($SSLLabs_Endpoint.details.cert.revocationStatus -eq 5) {
                Write-Host "[INFO] Revocation Status: Internal error" -ForegroundColor Red
            }
            Write-Host "`n"
            if($showChain) {
                Write-Host "[INFO] Certificate Chain"
                Write-Host "[INFO] ------------------"
                Write-Host "[INFO]"
                ForEach($Certificate in $SSLLabs_Endpoint.details.chain.certs) {
                    Write-Host "[INFO] Label:"$Certificate.label
                    Write-Host "[INFO] Subject:"$Certificate.subject
                    Write-Host "[INFO] Fingerprint SHA1:"$Certificate.sha1Hash -ForegroundColor Gray
                    Write-Host "[INFO] Pin SHA256:"$Certificate.pinSha256 -ForegroundColor Gray
                    Write-Host "[INFO] Issuer Label:"$Certificate.issuerLabel
                    Write-Host "[INFO] Issuer Subject:"$Certificate.issuerSubject
                    Write-Host "[INFO] Signature Algorithm:"$Certificate.sigAlg
                    Write-Host "[INFO] Key Algorithm:"$Certificate.keyAlg
                    Write-Host "[INFO] Key Size:"$Certificate.keySize
                    Write-Host "[INFO] Key Strength:"$Certificate.keyStrength
                    if($Certificate.revocationStatus -eq 0) {
                        Write-Host "[INFO] Revocation Status: Not checked" -ForegroundColor Gray
                    }
                    elseif($Certificate.revocationStatus -eq 1) {
                        Write-Host "[INFO] Revocation Status: Bad (certificate revoked)" -ForegroundColor Red
                    }
                    elseif($Certificate.revocationStatus -eq 2) {
                        Write-Host "[INFO] Revocation Status: Good (not revoked)" -ForegroundColor Green
                    }
                    elseif($Certificate.revocationStatus -eq 3) {
                        Write-Host "[INFO] Revocation Status: Revocation check error" -ForegroundColor Red
                    }
                    elseif($Certificate.revocationStatus -eq 4) {
                        Write-Host "[INFO] Revocation Status: No revocation information" -ForegroundColor Gray
                    }
                    elseif($Certificate.revocationStatus -eq 5) {
                        Write-Host "[INFO] Revocation Status: Internal error" -ForegroundColor Red
                    }
                    Write-Host "[INFO] Certificate Raw Data:"
                    Write-Host $Certificate.raw
                    Write-Host ""
                }
            }

            Write-Host "[INFO] Supported Protocols"
            Write-Host "[INFO] ------------------"
            Write-Host "[INFO]"
            ForEach($Protocol in $SSLLabs_Endpoint.details.protocols) {
                if(($Protocol.Name -match "TLS") -and ($Protocol.version -match "1.2")) {
                    Write-Host "[INFO]"$Protocol.name $Protocol.version -ForegroundColor Green
                }
                elseif(($Protocol.Name -match "TLS") -and (($Protocol.version -match "1.1") -or ($Protocol.version -match "1.0"))) {
                    Write-Host "[INFO]"$Protocol.name $Protocol.version -ForegroundColor Yellow
                }
                else {
                    Write-Host "[INFO]"$Protocol.name $Protocol.version -ForegroundColor Red
                }
            }
            Write-Host "`n"
            Write-Host "[INFO] Cipher Suites"
            Write-Host "[INFO] ------------------"
            Write-Host "[INFO]"
            ForEach($Suite in $SSLLabs_Endpoint.details.suites.list) {
                if($Suite.ecdhBits -ne $null) {
                    Write-Host "[INFO] Suite Name:"$Suite.name
                    Write-Host "[INFO] Cipher Strength:"$Suite.cipherStrength
                    Write-Host "[INFO] ECDH Bits:"$Suite.ecdhBits
                    Write-Host "[INFO] ECDH Strength:"$Suite.ecdhStrength
                    Write-Host ""
                }
                else {
                    Write-Host "[INFO] Suite Name:"$Suite.name
                    Write-Host "[INFO] Cipher Strength:"$Suite.cipherStrength
                    Write-Host ""
                }
            }
            Write-Host "`n"
            Write-Host "[INFO] Protocol Details"
            Write-Host "[INFO] ------------------"
            Write-Host "[INFO]"
            if($SSLLabs_Endpoint.details.drownVulnerable -eq $false) {
                Write-Host "[INFO] DROWN Vulnerable:"$SSLLabs_Endpoint.details.drownVulnerable -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] DROWN Vulnerable:"$SSLLabs_Endpoint.details.drownVulnerable -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.renegSupport -eq 1) {
                Write-Host "[INFO] Secure Renegotiation: Insecure client-initiated renegotiation is supported" -ForegroundColor Red
            }
            elseif($SSLLabs_Endpoint.details.renegSupport -eq 2) {
                Write-Host "[INFO] Secure Renegotiation: Secure renegotiation is supported" -ForegroundColor Green
            }
            elseif($SSLLabs_Endpoint.details.renegSupport -eq 4) {
                Write-Host "[INFO] Secure Renegotiation: Secure client-initiated renegotiation is supported" -ForegroundColor Green
            }
            elseif($SSLLabs_Endpoint.details.renegSupport -eq 8) {
                Write-Host "[INFO] Secure Renegotiation: Server requires secure renegotiation support" -ForegroundColor Green
            }
            if($SSLLabs_Endpoint.details.vulnBeast -eq $false) {
                Write-Host "[INFO] BEAST attack:"$SSLLabs_Endpoint.details.vulnBeast -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] BEAST attack:"$SSLLabs_Endpoint.details.vulnBeast -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.poodle -eq $false) {
                Write-Host "[INFO] Poodle (SSLv3) Vulnerable:"$SSLLabs_Endpoint.details.poodle -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Poodle (SSLv3) Vulnerable:"$SSLLabs_Endpoint.details.poodle -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.poodleTls -eq -3) {
                Write-Host "[INFO] Poodle (TLS) Vulnerable: Timeout" -ForegroundColor Gray
            }
            elseif($SSLLabs_Endpoint.details.poodleTls -eq -2) {
                Write-Host "[INFO] Poodle (TLS) Vulnerable: TLS not supported" -ForegroundColor Red
            }
            elseif($SSLLabs_Endpoint.details.poodleTls -eq -1) {
                Write-Host "[INFO] Poodle (TLS) Vulnerable: Test failed" -ForegroundColor Gray
            }
            elseif($SSLLabs_Endpoint.details.poodleTls -eq 0) {
                Write-Host "[INFO] Poodle (TLS) Vulnerable: Unknown" -ForegroundColor Gray
            }
            elseif($SSLLabs_Endpoint.details.poodleTls -eq 1) {
                Write-Host "[INFO] Poodle (TLS) Vulnerable: False" -ForegroundColor Green
            }
            elseif($SSLLabs_Endpoint.details.poodleTls -eq 2) {
                Write-Host "[INFO] Poodle (TLS) Vulnerable: True" -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.fallbackScsv -eq $true) {
                Write-Host "[INFO] Downgrade attack prevention: Yes, TLS_FALLBACK_SCSV supported" -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Downgrade attack prevention: No, TLS_FALLBACK_SCSV is not supported" -ForegroundColor Gray
            }
            if($SSLLabs_Endpoint.details.compressionMethods -eq 0) {
                Write-Host "[INFO] SSL/TLS compression: False" -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] SSL/TLS compression: True" -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.supportsRc4 -eq $false) {
                Write-Host "[INFO] RC4 Weakness:"$SSLLabs_Endpoint.details.supportsRC4 -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] RC4 Weakness:"$SSLLabs_Endpoint.details.supportsRC4 -ForegroundColor Red
            }
            Write-Host "[INFO] Heartbeat (Extension):"$SSLLabs_Endpoint.details.heartbeat
            if($SSLLabs_Endpoint.details.heartbleed -eq $false) {
                Write-Host "[INFO] Heartbleed (Vulnerable):"$SSLLabs_Endpoint.details.heartbleed -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Heartbleed (Vulnerable):"$SSLLabs_Endpoint.details.heartbleed -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.openSslCcs -eq -1) {
                Write-Host "[INFO] OpenSSL CCS Vulnerable: Test failed" -ForegroundColor Gray
            }
            elseif($SSLLabs_Endpoint.details.openSslCcs -eq 0) {
                Write-Host "[INFO] OpenSSL CCS Vulnerable: Unknown" -ForegroundColor Gray
            }
            elseif($SSLLabs_Endpoint.details.openSslCcs -eq 1) {
                Write-Host "[INFO] OpenSSL CCS Vulnerable: False" -ForegroundColor Green
            }
            elseif($SSLLabs_Endpoint.details.openSslCcs -eq 2) {
                Write-Host "[INFO] OpenSSL CCS Vulnerable: Possibly vulnerable, but not exploitable" -ForegroundColor Red
            }
            elseif($SSLLabs_Endpoint.details.openSslCcs -eq 3) {
                Write-Host "[INFO] OpenSSL CCS Vulnerable: True" -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.logjam -eq $false) {
                Write-Host "[INFO] Logjam Vulnerable:"$SSLLabs_Endpoint.details.logjam -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] Logjam Vulnerable:"$SSLLabs_Endpoint.details.logjam -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.freak -eq $false) {
                Write-Host "[INFO] FREAK Vulnerable:"$SSLLabs_Endpoint.details.freak -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] FREAK Vulnerable:"$SSLLabs_Endpoint.details.freak -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.forwardSecrecy -eq 1) {
                Write-Host "[INFO] Forward Secrecy: With some browsers" -ForegroundColor Yellow
            }
            elseif($SSLLabs_Endpoint.details.openSslCcs -eq 2) {
                Write-Host "[INFO] Forward Secrecy: With modern browsers" -ForegroundColor Gray
            }
            elseif($SSLLabs_Endpoint.details.openSslCcs -eq 4) {
                Write-Host "[INFO] Forward Secrecy: Yes (with most browsers) ROBUST" -ForegroundColor Green
            }
            if($SSLLabs_Endpoint.details.supportsNpn -eq $true) {
                Write-Host "[INFO] NPN: False"
            }
            else {
                Write-Host "[INFO] NPN: True"
            }
            if($SSLLabs_Endpoint.details.sessionResumption -eq 0) {
                Write-Host "[INFO] Session resumption (caching): Not Enabled"
            }
            elseif($SSLLabs_Endpoint.details.sessionResumption -eq 1) {
                Write-Host "[INFO] Session resumption (caching): Endpoints returns session ID, but sessions are not resumed" -ForegroundColor Yellow
            }
            elseif($SSLLabs_Endpoint.details.sessionResumption -eq 2) {
                Write-Host "[INFO] Session resumption (caching): Enabled"
            }
            if(($SSLLabs_Endpoint.details.sessionTickets -eq 0) -or ($SSLLabs_Endpoint.details.sessionTickets -eq $null)) {
                Write-Host "[INFO] Session resumption (tickets): Not Enabled"
            }
            elseif($SSLLabs_Endpoint.details.sessionTickets -eq 1) {
                Write-Host "[INFO] Session resumption (tickets): Supported"
            }
            elseif($SSLLabs_Endpoint.details.sessionTickets -eq 2) {
                Write-Host "[INFO] Session resumption (tickets): Implementation is faulty" -ForegroundColor Yellow
            }
            elseif($SSLLabs_Endpoint.details.sessionTickets -eq 4) {
                Write-Host "[INFO] Session resumption (tickets): Server is intolerant to the extension"
            }
            if($SSLLabs_Endpoint.details.ocspStapling -eq $true) {
                Write-Host "[INFO] OCSP stapling: False"
            }
            else {
                Write-Host "[INFO] OCSP stapling: True"
            }
            if(($SSLLabs_Endpoint.details.dhUsesKnownPrimes -eq 0) -or ($SSLLabs_Endpoint.details.dhUsesKnownPrimes -eq $null)) {
                Write-Host "[INFO] Uses common DH primes: False" -ForegroundColor Green
            }
            elseif($SSLLabs_Endpoint.details.dhUsesKnownPrimes -eq 1) {
                Write-Host "[INFO] Uses common DH primes: Yes, but they're not weak" -ForegroundColor Yellow
            }
            elseif($SSLLabs_Endpoint.details.dhUsesKnownPrimes -eq 2) {
                Write-Host "[INFO] Uses common DH primes: Yes and they're weak" -ForegroundColor Red
            }
            if($SSLLabs_Endpoint.details.dhYsReuse -eq $null) {
                Write-Host "[INFO] DH public server param (Ys) reuse: False" -ForegroundColor Green
            }
            else {
                Write-Host "[INFO] DH public server param (Ys) reuse: True" -ForegroundColor Red
            }
            Write-Host "`n"
        }    
    }
    else {
        Write-Host "[ERROR] Your request timed out. Please try again later!" -ForegroundColor Red
        break
    }
}
else {
    Write-Host "[Error] SSLLabs API is currently not available!" -ForegroundColor Red
    break
}


}