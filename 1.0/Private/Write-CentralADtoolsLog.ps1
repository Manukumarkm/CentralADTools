Function Write-CentralADtoolsLog{

    <#
    .SYNOPSIS
    To Write log to the provided file path, and also display the log content on the powershell console

    .DESCRIPTION
    This function will write log to the provided file path, and also display the log content on the powershell console

    .PARAMETER LogData
    Data that needs to be written as log

    .PARAMETER Type 
    The type of logs "Error", "Warning", "Info")

    .PARAMETER Logfile
    Log file path to save logs
       

    .EXAMPLE
    Write-CentralADToolsLog -Logdata "This is a test error log info" -type Error -Logfile C:\temp\pap.log"

    The above exapmple will write error log in the log C:\temp\pap.log" file and on the powershell console

    .EXAMPLE
    Write-CentralADToolsLog -Logdata "This is a test info log info" -type Error -Logfile C:\temp\pap.log"
    The above exapmple will write an info log in the log C:\temp\pap.log" file and on the powershell console

    .NOTES
   
    #>

    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'Event Data',
        Position = 0)]
        [string]
        $LogData,

        [Parameter(Mandatory = $True, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'Log type',
        Position = 1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("Error", "Warning", "Info","Log")]
        [String]
        $Type,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'Log File path',
        Position = 2)]
        [string]
        $Logfile = "C:\Temp\CentralADTools\Logs.txt",

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        HelpMessage = 'Skip new line',
        Position = 3)]
        [switch]
        $NoNewLine
    )

    if (!(Test-Path "C:\Temp\CentralADTools\")) {
        New-Item -Path $Logfile -ItemType Directory -Force | Out-Null
    }
    $Logfile = "C:\Temp\CentralADTools\CentralADTools_Logs_{0}.txt" -f $(Get-Date -Format dd_MMM_yyyy)
    Switch($Type){

                "Error" {
                            Add-Content -Path $LogFile "$(Get-date) `t [$Type] $LogData" -ErrorAction Stop
                            Write-Host "$(Get-date) `t [$Type] $LogData" -f Red
                                                        
                           }
                
                "Warning" {

                            Add-Content -Path $LogFile "$(Get-date) `t [$Type] $LogData" -ErrorAction Stop
                            Write-Host "$(Get-date) `t [$Type] $LogData" -f Yellow
                            
                           }

                "Info"   {

                            Add-Content -Path $LogFile "$(Get-date) `t [$Type] $LogData" -ErrorAction Stop
                            Write-Host "$(Get-date) `t [$Type] $LogData" -f Cyan
                            
        
                           }
                "Log"   {

                            Add-Content -Path $LogFile "$(Get-date) `t [$Type] $LogData" -ErrorAction Stop
                            
        
                           }


                }#END Of Switch


} #End of function Write-CentralADtoolsLog