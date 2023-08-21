Function Get-AccessTokenSecret{

    <#
        .SYNOPSIS
        This function is for generating oAuth access token using Client Secret and application ID
    
        .DESCRIPTION
        This function is for generating oAuth access token using Client Secret and application ID
    
        
        .PARAMETER ApplicationId 
        Application ID, which is already registered in the azure AD / oAuth provider
    
        .PARAMETER ApplicationSecret
        Application secret generated from Azure AD / oAuth provider for the given Application
    
        .PARAMETER $AuthEndpointUrl 
        oAuth provider enpoint to generate the access token.

        .PARAMETER $Scope 
        oAuth access scope values values.
    
        
    
        .EXAMPLE
        Get-AccessTokenSecret -ApplicationId "JKKg-LKHlj-wknr-Asdasfd" -ApplicationSecret "HJKhjkghfjhv-LKJjg-LKlhgkjgkj" -Scope "https://graph.microsoft.com/.default" -AuthEndpointUrl "https://login.microsoftonline.com/$($TenantId)/oauth2/v2.0/token"
    
        The above exapmple will generate an azureAD access token using the provided Application ID and application secret for the url scoped "https://graph.microsoft.com"
        
        .EXAMPLE

        Get-AccessTokenSecret -AuthEndpointUrl "https://login.microsoftonline.com/{$env:TENANTID}/oauth2/token" -ApplicationId "SAmpleApplication" -ApplicationSecret "SampleSecret" -Scope "basic userinfo organization"
        The above exapmple will generate an access token using the provided Application ID and application secret for the url scoped "basic userinfo organization" from the auth endpoint ""https://login.microsoftonline.com/{$env:TENANTID}/oauth2/token""
        
        
        .NOTES
        
        #>
    
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'oAuth application ID',
            Position = 0)]
            [string]$ApplicationId,
            
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'oAuth Application Secret',
            Position = 1)]
            [string]$ApplicationSecret,
            
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Auth end point url',
            Position = 2)]
            [string]$AuthEndpointUrl,
            
            [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'oAuth Scope',
            Position = 3)]
            [string]$Scope       
            )
    
    begin{
            Write-CentralADToolsLog -Type Info -LogData "Initializing network connection to the access Token endpoint."
            $Pattern = "https?://(?:www\.)?([^/]+)"
            $Endpoint = $AuthEndpointUrl |  Select-String -Pattern $pattern | ForEach-Object { $_.Matches.Groups[1].Value }
            
            $retryCount = 3
            $I = 1
            $retryInterval = 3
            $ValidationStatus = $false
            $Port = 443

            do {
                try {
                    $ValidationStatus = Test-NetConnection $Endpoint -Port $Port -InformationLevel Quiet
                } 
                catch {
                    Write-CentralADToolsLog -Type Error -LogData "An error occurred: $($_.Exception.Message)"
                    Start-Sleep -Seconds $retryInterval
                }
                $I++
            } until (($I -eq $retryCount) -or ($ValidationStatus))

            

            
            
            
            # OAuth Body Access Token Request
            $authBody = @{
                            client_id = $ApplicationId;
                            client_secret = $ApplicationSecret;    
                            # The v2 endpoint for OAuth uses scope instead of resource
                            scope = $Scope   
                            grant_type = 'client_credentials'
                          }
    
            # Parameters for OAuth Access Token Request
            $authParams = @{
                            URI = $AuthEndpointUrl #$oAuthTokenEndpoint
                            Method = 'POST'
                            ContentType = 'application/x-www-form-urlencoded'
                            Body = $authBody
                           }
        }

    Process{

            If($ValidationStatus){
                
                                    # Get Access Token
                                    Try {
                                            $authResponseObject = Invoke-RestMethod @authParams -ErrorAction Stop
                                            Write-CentralADToolsLog -Type Info -LogData "Access token generated successfully"
                                            Return $authResponseObject
                                        }

                                    Catch{
                                            Write-Error "$($_.Exception.message)"
                                        }
                                 }

               Else{
                        Write-CentralADToolsLog -Type Info -LogData "Failed to initialize TCP $Port conection to the $Endpoint, cannot generate the Access token"
                        Return "NoConnection"
                    }
        }

    
} #End of function Get-AccessTokenSecret