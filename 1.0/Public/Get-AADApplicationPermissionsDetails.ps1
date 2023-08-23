function Get-AADApplicationPermissionsDetails{
    [CmdletBinding(DefaultParameterSetName = "NoFilter")]
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Azure AD Tenant ID")]
        [string]$TenantId,

        [Parameter(Mandatory = $true, HelpMessage = "Client ID (Application ID)")]
        [string]$ClientId,

        [Parameter(Mandatory = $true, HelpMessage = "Client Secret (Application Secret)")]
        [string]$ClientSecret,

        [Parameter(ParameterSetName = "ApplicationIDFilter", Mandatory = $true, HelpMessage = "Filter by AzureAD Application ID")]
        [string]$ApplicationID,

        [Parameter(ParameterSetName = "ApplicationNameFilter", Mandatory = $true, HelpMessage = "Filter by AzureAD Application Name")]
        [string]$ApplicationName
    )

    begin {
        $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $ScopeV2 = "https://graph.microsoft.com/.default"
        $GRAPH_URL = "https://graph.microsoft.com"
        $applications = @()
        $PermissionsDetails = @()
        $i = 1

        Import-Module centralADTools -Force

        $accessToken = Get-AccessTokenSecret -ApplicationId $ClientId -ApplicationSecret $ClientSecret -AuthEndpointUrl $tokenEndpoint -Scope $ScopeV2
        
        if (($PSCmdlet.ParameterSetName -eq "ApplicationIDFilter") -and $ApplicationName) {
            Write-Error "Please provide either ApplicationID or ApplicationName, not both."
            return
        }

        if ($PSCmdlet.ParameterSetName -eq "ApplicationIDFilter") {
            $applications = Get-ApplicationDetailsGraphAPI -AccessToken $accessToken -ApplicationID $ApplicationID
        }
        elseif ($PSCmdlet.ParameterSetName -eq "ApplicationNameFilter") {
            $applications = Get-ApplicationDetailsGraphAPI -AccessToken $accessToken -ApplicationName $ApplicationName
        }
        else {
            $applications = Get-ApplicationDetailsGraphAPI -AccessToken $accessToken
        }
    }

    process {
        try {
            foreach ($Application in $applications) {
                Write-Host "[$i out of $($applications.count)] - Fetching the details of the application - $($Application.DisplayName)" -ForegroundColor Green

                $APIPermissions = $Application.requiredResourceAccess

                $PermissionsDetails += foreach ($APIPermission in $APIPermissions) {
                    foreach ($PermissionID in $APIPermission.resourceAccess.ID) {
                        Get-ApplicationAPIPermission -AccessToken $accessToken -ServicePrincipalID $APIPermission.resourceAppId -PermissionId $PermissionID |`
                        Select-Object @{N="ApplicationName";E={$Application.displayName}}, @{N="ApplicationID";E={$Application.id}}, APIName, ID, PermissionType, PermissionName, PermissionID
                    }
                }

                $i++
            }

            return $PermissionsDetails
        } 
        catch {
            Write-Error "An error occurred: $($_.Exception.Message)"
        }
    }
}