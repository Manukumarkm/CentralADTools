Function New-gMSAAccount {

    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Mandatory=$false,
        ParameterSetName = 'fileInput')]
        $InputFile
    )
    
    

    if ($PSBoundParameters.ContainsKey('Inputfile')){
        Write-CentralADToolsLog -Type Info -LogData "gMSA creation from Template file $InputFile is initiated"
        $Inputs = Import-Csv -Path $InputFile -Delimiter "," | Where-Object{$_.gMSA_Name -ne ""}
        
            foreach($Input in $Inputs[1..$Inputs.Count]){

                    
                    $PrincipalstoRetrivePass = (($Input.ServerName).Split(',')).ForEach({ $_.Split('.')[0] + '$' }) #-join ','
                    #$PrincipalstoRetrivePass = EU50TSVP403$,EU50TSVP113$
                    $ManagerDN = (Get-ADUser -Identity $Input.ManagerPUID).DistinguishedName
                    $OUName = "Managed Service Accounts"
                    $params = @{
                                    name = $input.gMSA_Name
                                    SamAccountName = '{0}$' -f $Input.gMSA_Name
                                    AccountNotDelegated = $true
                                    Description = $Input.Description
                                    DisplayName = $input.gMSA_Name
                                    KerberosEncryptionType = 'AES128', 'AES256'
                                    Path = 'CN={0},{1}' -f $OUName,((($env:USERDNSDOMAIN).Split('\.')).ForEach({ "DC=$_" }) -join ',').tostring()
                                    enabled = $True
                                    TrustedForDelegation = $false
                                    PrincipalsAllowedToRetrieveManagedPassword = $PrincipalstoRetrivePass
                                    DNSHostName = '{0}.{1}' -f $input.gMSA_Name,$Env:USERDNSDOMAIN
                                    OtherAttributes = @{

                                                        c=$Input.C
                                                        co=$Input.Co
                                                        company=$Input.Company
                                                        department=$input.Department
                                                        employeeType=$Input.Tier
                                                        givenName=$input.gMSA_Name
                                                        l=$Input.city
                                                        mail=$input.Mail
                                                        manager = $ManagerDN
                                                        #ProtectedFromAccidentalDeletion = $true
                                                    }
                                    
                                }
                        Try{
                        New-ADServiceAccount @params -ErrorAction Stop
                        Write-CentralADToolsLog -Type Info -LogData "gMSA account $($input.gMSA_Name) created successfully"
                        }
                        Catch{
                            Write-CentralADToolsLog -Type Error -LogData "An error occured during the gMSA creation"
                            Write-CentralADToolsLog -Type Error -LogData "$($_.Exception.Message)"
                        }
                    
                    } #END OF FOREACH
                }#END OF IF
        
        
}#END OF FUNCTION New-gMSAAccount