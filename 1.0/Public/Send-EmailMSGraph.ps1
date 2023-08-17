
Function Send-EmailMSGraph {

    <#
        .SYNOPSIS
        This function send email message using MSGraphAPI.
    
        .DESCRIPTION
        This function send email message using MSGraphAPI.
            
   
        .PARAMETER To
        Mail receipient address.
    
        .PARAMETER To
        Mail Cc receipient address.
    
        .PARAMETER From
        Email sender address.
    
        .PARAMETER Body
        Email message content in HTML format string format.
    
        .PARAMETER Subject
        Email Subject text.
    
    
        .PARAMETER AttachmentFile
        Email attachment file path.
    
    
    
            
        .EXAMPLE
    
        
        .NOTES
        Created By - Manukumar KM
        last updated - 30/March/2023
        
    #>
    
        [CmdletBinding()]
        param(
                [Parameter(Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Email receipient address',
                Position = 1)]
                [string[]]$To,
    
                [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Email Cc receipient address',
                Position = 2)]
                [string[]]$Cc,
            
                [Parameter(Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Email sender address',
                Position = 3)]
                [string]$From,
                
                
                [Parameter(Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Email Subject',
                Position = 4)]
                [string]$Subject,
    
                [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Email body',
                Position = 5)]
                [string]$Body,
                
                [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Attachment file(s)',
                Position = 6)]
                [ValidateScript({Test-Path $_ -PathType Leaf})]
                [string[]]$Attachments,
                
                [Parameter(Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure Tenant ID',
                Position = 7)]
                [string]$TenantID,
    
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure AD application ID',
                Position = 8)]
                [string]$AppId,
    
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Certificate thumbprint which is already updated AzureAD and installed on the Server where the script is running',
                Position = 9)]
                [string]$CertThumbprint
    
        )
    
    
    
    ##Define Functions##
    
    function New-FileAttachment {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [ValidateScript({Test-Path $_ -PathType Leaf})]
            [string[]]$FileNames
        )
    
        $fileAttachments = @()
        for ($i = 0; $i -lt $FileNames.Length; $i++) {
            
            $FileName=(Get-Item -Path $FileNames[$i]).name
            $base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($FileNames[$i]))
            
            $fileAttachment = @{
                "@odata.type" = "#microsoft.graph.fileAttachment"
                "name" = $FileName
                "contentType" = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                "contentBytes" = $base64string
            }
            $fileAttachments += $fileAttachment
        }
    
        return $fileAttachments
    }
    
    function Format-Address {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory = $true)]
            [string[]]$Address
        )
    
        $AddressLists = @()
        for ($i = 0; $i -lt $Address.Length; $i++) {
            
                   
            $AddressList = @{
                "emailAddress" = @{"address" = $Address[$i] }
            }
    
            $AddressLists += $AddressList
        }
    
        return $AddressLists
    }
    
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
        Cloud or API url for which the access token to be generated for
    
    
        .EXAMPLE
       
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
    
                [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure Environment url to generate access token for',
                Position = 2)]
                [string]$EnvironmentUrl = "https://graph.microsoft.com",
    
                [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure AD tenant ID',
                Position = 3)]
                [string]$TenantID,
    
                [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
                HelpMessage = 'Azure AD OAuth Token endpoint url',
                Position = 4)]
                [string]$oAuthTokenEndpoint = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token"
                
    
                     
              )
    
         #Read more - https://learn.microsoft.com/en-us/azure/active-directory/develop/active-directory-certificate-credentials
         Write-Verbose "Initiated Access Token request using function Get-AccessTonkenCERT"
    
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
             Write-Verbose "Access token generated Successfully"
             Return $authResponseObjectcert
           }
     Catch{
    
             Write-Error "ERROR :: $($_.Exception.Message)"
             Return $false
           }
    
    } #End of function Get-AccessTonkenCERT  
    
    
        #Enforcing tls 1.2 as microsoft Azure only support TLS1.2
        $TLS12Protocol = [System.Net.SecurityProtocolType] 'Ssl3 , Tls12'
        [System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol
        
        
        $MsGraphTokenParams =@{
            
                                ApplicationId = $AppId
                                CertThumbprint = $CertThumBprint
                                TenantID = $TenantID
                              }
        Try{
                Write-Verbose "Generating access token"
                $msGraphAccessTokenResponse = Get-AccessTonkenCERT @MsGraphTokenParams -ErrorAction stop
        }
        Catch{
    
                Write-Error "An error occure while generating the access token"
                Break
        }
    
    
    $MessageParams = @{
                        "URI"         = "https://graph.microsoft.com/v1.0/users/$From/sendMail"
                        "Headers"     = @{
                                            'Content-Type'  = "application/json"
                                            'Authorization' = "Bearer $($msGraphAccessTokenResponse.access_token)" 
                                          }
                        "Method"      = "POST"
                        "ContentType" = 'application/json'
    }
    
    $message = @{
                    "subject"      = $Subject
                    "body"         = @{
                                        "contentType" = 'HTML' 
                                        "content"     = $Body 
                                      }
                    "toRecipients" = @($(Format-Address -Address $To))
    }
    
    if($null -ne $Cc){
        $message["ccRecipients"] = @($(Format-Address -Address $Cc))
    }
    
    if($null -ne $Attachments){
        $message["attachments"] = @($(New-FileAttachment -FileNames $Attachments))
    }
    
    $MessageParams["Body"] = ConvertTo-JSON @{
                                "message" = $message
                                }  -Depth 10
    
        
        
    If(tnc graph.microsoft.com -Port 443 -InformationLevel Quiet){
        
        Try{
                Write-Verbose "Starting email message to - $($To.GetEnumerator())"
                Invoke-RestMethod @Messageparams -ErrorAction Stop
                Write-Host "Email message sent successfuly" -f Green
            
            }
        Catch{
                Write-Error  "An error occured while sending email - ERROR :: $($_.exception.message)"
        }
    }
    Else{
        Write-Error "Communication over 443 to graph.microsoft.com - failed"
    }
    
    
} #End of function Send-EmailMSGraph