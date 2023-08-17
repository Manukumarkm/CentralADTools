Function Set-ADPermission {

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
        HelpMessage = 'Permission to be added',
        Position = 2)]$Permission,
    
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'Distinguished name (DN) of the AD object to which the permisison to be added',
        Position = 3)][String[]]$ResourceDN,
    
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'samAccountName of the idenity to which the permissions to be granted',
        Position = 4)]$IdentityReferenceSamAccountName,
        [String]$InheritanceType
    
    )
    
    Write-CentralADToolsLog -Logdata "Set-ADPermission initialized by $($env:USERNAME)" -Type Info
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
        Try{
    
            $IdentitySID = (Get-ADObject -Server $PreferedServer -Filter {samAccountName -eq $IdentityReferenceSamAccountName} -SearchBase $Domain.DistinguishedName -SearchScope Subtree -ErrorAction Stop -Properties objectSID).objectSID.Value
            $IdentityReferenceSID= New-Object System.Security.Principal.SecurityIdentifier $IdentitySID
            #return $IdentityReferenceSID
        }
    
        Catch{
    
            Write-CentralADToolsLog -Logdata "Provided identity samAccountName - $IdentityReferenceSamAccountName not found in the domain $($Domain.DNSRoot)" -type Error
            Break
        }
    
        $Inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::$InheritanceType
        #Return $Inheritance
        $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $IdentityReferenceSID, $Permission, $GrantType, $Inheritance
        $ResourceACL.AddAccessRule($ACE)
        Try{
            Set-ACL -ACLObject $ResourceACL -Path $ResourcePath -ErrorAction Stop
            Write-CentralADToolsLog -Logdata "Successfully added the below ACE into the ACL of $Resource" -type info
            Write-CentralADToolsLog -Logdata $($ACE | ConvertTo-json) -Type info
        }
        Catch{

            Write-CentralADToolsLog -Logdata "Failed the below ACE into the ACL of $Resource" -type error
            Write-CentralADToolsLog -Logdata "$($_.Exception.Message)" -type error

        }
    
    }
    
    } #END of Function Set-ADPermission