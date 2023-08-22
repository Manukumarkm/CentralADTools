function Get-ApplicationDetailsGraphAPI{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Access token obtained using Get-AccessTokenSecret or Get-AccessTokenCert")]
        $AccessToken,

        [Parameter(HelpMessage = "Application name to filter.")]
        [string]$ApplicationName,

        [Parameter(HelpMessage = "Application ID to filter.")]
        [string]$ApplicationId,

        [Parameter(Mandatory = $false, HelpMessage = "Limit the number of applications to be returned from the top list")]
        $Limit = 999
    )

    begin {
        Write-CentralADToolsLog -Type Info -LogData "[$($MyInvocation.MyCommand.Name)] Executing the function"
        $headers = @{
            "Content-Type"  = "application/json"
            "Authorization" = "$($AccessToken.token_type) $($AccessToken.access_token)"
        }

        $baseUrl = "https://graph.microsoft.com"
        $appUrl = 'applications?$top={0}' -f $Limit
        $Results = @()
    }

    process {
        if ($ApplicationName) {
            $filter = "displayName eq '$ApplicationName'"
            $appUrl += "&`$filter=$filter"
        } elseif ($ApplicationId) {
            $filter = "appId eq '$ApplicationId'"
            $appUrl += "&`$filter=$filter"
        }

        $queryUrl = "$baseUrl/v1.0/$appUrl"
        Write-CentralADToolsLog -Type Info -LogData "[$($MyInvocation.MyCommand.Name)] The query url is $queryUrl" 
        try {
                Write-CentralADToolsLog -Type Info -LogData "[$($MyInvocation.MyCommand.Name)] Fetching the application details in-progress"
                $appResponse = Invoke-RestMethod -Uri $queryUrl -Headers $headers -Method Get
                $NextLink = $appResponse."@odata.nextLink"
                $Results += $appResponse.value
                    While($NextLink){
                            $appResponse = Invoke-RestMethod -Uri $NextLink -Headers $headers -Method Get
                            if ($NextLink){
                                    $NextLink = $appResponse."@odata.nextLink"
                                }
                                $Results += $appResponse.value
                        }
            Write-CentralADToolsLog -Type Info -LogData "[$($MyInvocation.MyCommand.Name)] Fetching the application details - Success"
            Return $Results
            }


        catch {
            
            Write-CentralADToolsLog -Type Error -LogData "[$($MyInvocation.MyCommand.Name)] An error occurred while querying the Microsoft Graph API: $($_.Exception.Message)"

        }
    }
}

