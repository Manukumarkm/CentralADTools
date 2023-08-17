Function Remove-ADPermission {

    [CmdletBinding()]
    Param (
    
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'To connect a prefered server',
        Position = 0)]$Server,
    
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'Permission grant type Allow/Deny',
        Position = 1)]
        [ValidateSet('Allow', 'Deny')]
        $GrantType,
    
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'Permission to be Removed',
        Position = 2)]$Permission,
    
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'Distinguished name (DN) of the AD object from which the permisison to be removed',
        Position = 3)][String[]]$ResourceDN,
    
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'samAccountName of the idenity to which the permissions to be removed',
        Position = 4)]$IdentityReferenceSamAccountName,
        [String]$InheritanceType
    
    )
    
    Write-CentralADToolsLog -Logdata "Remove-ADPermission initialized by $($env:USERNAME)" -Type Info
    $Domain = Get-ADDomain
    
    if($Server){
    $PreferedServer = $Server
    }
    Else{
    $PreferedServer = (Get-ADDomainController -Discover -ForceDiscover -NextClosestSite -Writable).Name
    }
    
    foreach($Resource in $ResourceDN){
    
        $ResourcePath = "AD:\$Resource"
        $ResourceACL = $ResourcePath | Get-Acl
           

        $ACE= $ResourceACL.Access | Where-Object{$_.IdentityReference -match $IdentityReferenceSamAccountName -and $_.ActiveDirectoryRights -eq $Permission -and $_.InheritanceType -eq $InheritanceType -and $_.AccessControlType -eq $GrantType}
        
        If($ACE){
                Write-CentralADToolsLog -Logdata "Below ACE found based on the provided details" -type Info
                Write-CentralADToolsLog -Logdata $($ACE | ConvertTo-Json) -Type Info
                
                
                Try{
                    $ResourceACL.RemoveAccessRule($ACE) | Out-Null
                    Set-ACL -ACLObject $ResourceACL -Path $ResourcePath -ErrorAction Stop| Out-Null
                    Write-CentralADToolsLog -Logdata "Permission removed successfully" -Type Info
                    }

                    Catch {

                        Write-CentralADToolsLog -Logdata "Failed the below ACE into the ACL of $Resource" -type error
                        Write-CentralADToolsLog -Logdata "$($_.Exception.Message)" -type error

                        }

                }

        Else{
                Write-CentralADToolsLog -Logdata "$Resource `t NO ACE matching with the provided details." -type Info
                
                }

}

      
    
}#END of Function Remove-ADPermission