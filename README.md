# CentralADTools

## Overview

CentralADTools is a comprehensive PowerShell module designed to streamline and simplify common Active Directory administration tasks. This module is created to empower Active Directory administrators with efficient tools to manage day-to-day operations and enhance productivity.

## Features

- **Efficiency**: Simplify complex Active Directory tasks with user-friendly cmdlets and functions.
- **Automation**: Automate routine tasks to save time and reduce human errors.
- **Flexibility**: Perform a variety of actions related to user management, group management, permissions, and more.
- **Consistency**: Utilize a consistent and standardized interface for managing Active Directory objects.

## Available Cmdlets and Functions

- New-gMSAAccount: To create gMSA accounts from a csv input file
- Set-ADPermission: To set delegated permission on Active Directory objects or OUs.
- Remove-ADPermission: To remove a specific ACE entry from an active directory objects or OUs
- Send-EmailMSGraph: To send emails using MSGraph API with Application registration and certificate based authentication.
- Get-AccessTonkenCERT : To generate AzureAD access token using Certificate and application ID.
- Get-AccessTokenSecret : To generate access token using Client secret and application ID.
- Get-ApplicationDetailsGraphAPI : To fetch the application details from AzureAD via MSGraph API call.


## License
This project is licensed under the MIT License.

## Contact
For any questions or feedback, please contact me at manu_km@outlook.com.

## Installation

You can easily install the CentralADTools module from the PowerShell Gallery using the following command:

```powershell
Install-Module -Name CentralADTools
