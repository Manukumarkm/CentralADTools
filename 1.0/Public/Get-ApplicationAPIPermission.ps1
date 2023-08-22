function Get-ApplicationAPIPermission{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline = $true,Mandatory = $true, HelpMessage = "Access token obtained using Get-AccessTokenSecret or Get-AccessTokenCert")]
        $AccessToken,

        [Parameter(ValueFromPipeline = $true,Mandatory = $true,HelpMessage = "ServicePrincipal ID")]
        $ServicePrincipalID,

        [Parameter(ValueFromPipeline = $true,Mandatory = $true,HelpMessage = "API Permission ID")]
        $PermissionId

    )

    begin {
        Write-CentralADToolsLog -Type Info -LogData "[$($MyInvocation.MyCommand.Name)] Executing the function"
        $headers = @{
            "Content-Type"  = "application/json"
            "Authorization" = "$($AccessToken.token_type) $($AccessToken.access_token)"
        }

        $baseUrl = "https://graph.microsoft.com"
        $queryUrl = "$baseUrl/v1.0/servicePrincipals?`$filter=appId eq '$ServicePrincipalID'&`$select=DisplayName,ID,appRoles,oauth2PermissionScopes"
    }

    process {


        Write-CentralADToolsLog -Type Info -LogData "[$($MyInvocation.MyCommand.Name)] The query url is $queryUrl" 
        try {
                Write-CentralADToolsLog -Type Info -LogData "[$($MyInvocation.MyCommand.Name)] Fetching the permission details in-progress"
                $APIPermissions = Invoke-RestMethod -Uri $queryUrl -Headers $headers -Method Get
                $PermissionAppRoleName = $APIPermissions.value.AppRoles | Where-Object{$_.id -match $PermissionId}
                $PermissionScopeName =  $APIPermissions.value.oauth2PermissionScopes | Where-Object{$_.id -eq $PermissionId}

                If($PermissionAppRoleName){
                        
                $ResultData = [PSCustomObject]@{
                                            APIName = $APIPermissions.value.DisplayName
                                            ID = $APIPermissions.value.ID
                                            PermissionType = "Application"
                                            PermissionName = $PermissionAppRoleName.Value
                                            PermissionID = $PermissionAppRoleName.ID
                                            }
                }

                If($PermissionScopeName){
                        
                $ResultData = [PSCustomObject]@{
                                            APIName = $APIPermissions.value.DisplayName
                                            ID = $APIPermissions.value.ID
                                            PermissionType = "Delegated"
                                            PermissionName = $PermissionScopeName.Value
                                            PermissionID = $PermissionScopeName.ID
                                            }
                }

                Write-CentralADToolsLog -Type Info -LogData "[$($MyInvocation.MyCommand.Name)] Fetching the permission details - Success"
                Return $ResultData
            }


        catch {
            
            Write-CentralADToolsLog -Type Error -LogData "[$($MyInvocation.MyCommand.Name)] An error occurred while querying the Microsoft Graph API: $($_.Exception.Message)"

        }
    }
}