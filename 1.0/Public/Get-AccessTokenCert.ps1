Function Get-AccessTonkenCERT{

    <#
        .SYNOPSIS
        This function is for generating AzureAD access token using Certificate and application ID
    
        .DESCRIPTION
        This function is for generating AzureAD access token using Certificate and application ID
    
        
        .PARAMETER ApplicationId 
        Application ID, which is already registered in the azure AD
    
        .PARAMETER CertThumbprint
        Certificate thumbprint for authentication and generating the access token
    
        .PARAMETER EnvironmentUrl 
        Cloud or API url for which the access token to be generated / Scope
    
        .PARAMETER Logfile
        Log file path to save logs
    
        
    
        .EXAMPLE
        Get-AccessTonkenCERT -ApplicationId "JKKg-LKHlj-wknr-Asdasfd" -CertThumbprint "775B373B33B9D15B58BC02B184704332B97C3CAF" -EnvironmentUrl "https://graph.microsoft.com"
    
        The above exapmple will generate an azureAD access token using the provided Application ID and certificate thumbprint provided for the url "https://graph.microsoft.com"
        The certificate must be installed on the server where the script is executing, and the private key must be binded.
        
        .NOTES
        
        #>
    
        [CmdletBinding()]
        param (
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure AD application ID',
                Position = 0)]
                [string]$ApplicationId,
    
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Certificate thumbprint which is already updated AzureAD and installed on the Server where the script is running',
                Position = 1)]
                [string]$CertThumbprint,
    
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure Environment url to generate access token for',
                Position = 2)]
                [string]$EnvironmentUrl,
    
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure AD tenant ID',
                Position = 3)]
                [string]$TenantID,
    
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure AD OAuth Token endpoint url',
                Position = 4)]
                [string]$oAuthTokenEndpoint,
                
                [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Log File path',
                Position = 5)]
                [string]$Logfile = $Global:LogFile
                     
              )
    
         #Read more - https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
         Write-CentralADToolsLog -Type Info -LogData "Initiated Access Token request using function Get-AccessTonkenCERT"
    
         $Certificate = Get-Item Cert:\localMachine\My\$CertThumbprint
         $Scope = "$($EnvironmentUrl)/.default"  # Example: "https://graph.microsoft.com/.default"
    
    
         #Create base64 hash of certificate
         $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())
        
         # Create JWT timestamp for expiration
         $StartDate = (Get-Date "1970-01-01T00:00:00Z").ToUniversalTime()
         $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(5)).TotalSeconds # Token Expiry set to 5 mins
         $NotAfter = [math]::Round($JWTExpirationTimeSpan,0)
        
         # Create JWT validity start timestamp
         $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
         $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)
        
         # Create JWT header
         $JWTHeader = @{
             alg = "RS256"
             typ = "JWT"
             x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '=' #Use the CertificateBase64Hash and replace/strip to match web encoding of base64
         }
        
         # Create JWT payload
         $JWTPayLoad = @{
         
                aud = $oAuthTokenEndpoint # What endpoint is allowed to use this JWT
                exp = $NotAfter  # Expiration timestamp
                iss = $ApplicationId  # Issuer = your application
                jti = [guid]::NewGuid() # JWT ID: random guid
                nbf = $NotBefore # Not to be used before
                sub = $ApplicationId # JWT Subject
         }
        
         # Convert header and payload to base64
         $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
         $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)
        
         $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
         $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)
        
         # Join header and Payload with "." to create a valid (unsigned) JWT
         $JWT = $EncodedHeader + "." + $EncodedPayload
        
         # Get the private key object of your certificate
         $PrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate))
        
         # Define RSA signature and hashing algorithm
         $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
         $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
        
        
         # Create a signature of the JWT
         $Signature = [Convert]::ToBase64String(
             $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
         ) -replace '\+','-' -replace '/','_' -replace '='
        
         # Join the signature to the JWT with "."
         $JWT = $JWT + "." + $Signature
        
         # Create a hash with body parameters
         $Body = @{
             client_id = $ApplicationId
             client_assertion = $JWT
             client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
             scope = $Scope
             grant_type = "client_credentials"
        
         }
        
    
        
         # Use the self-generated JWT as Authorization
         $Header = @{
             Authorization = "Bearer $JWT"
         }
        
         # Splat the parameters for Invoke-Restmethod for cleaner code
         $Params = @{
             ContentType = 'application/x-www-form-urlencoded'
             Method = 'POST'
             Body = $Body
             Uri = $oAuthTokenEndpoint
             Headers = $Header
         }
     
    Try{   
             $authResponseObjectcert = Invoke-RestMethod @Params -ErrorAction Stop
             Write-CentralADToolsLog -LogData "Access token generated Successfully" -Type Info
             Return $authResponseObjectcert
           }
     Catch{
    
             Write-CentralADToolsLog -LogData "ERROR :: $($_.Exception.Message)" -Type Error
             Return $false
           }
    
    } #End of function Get-AccessTonkenCERT   