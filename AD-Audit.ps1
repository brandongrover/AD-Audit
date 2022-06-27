cls
# Variables
$email_ignore_list = ''
#$ignore_string = ''
$outputdir = "$($pwd)\Output\$(Get-Date -Format "yyyy-MM")"
$DomainController = ''

if (!(Test-Path $outputdir)) {
    New-Item -ItemType Directory -Path "$pwd\Output\" -Name "$(Get-Date -Format "yyyy-MM")"

    if (!(Test-Path $outputdir\Accounts)) {
        New-Item -ItemType Directory -Path $outputdir\ -Name "Accounts"
    }

    if (!(Test-Path $outputdir\Email)) {
        New-Item -ItemType Directory -Path $outputdir\ -Name "Email"
    }

    if (!(Test-Path $outputdir\Privileges)) {
        New-Item -ItemType Directory -Path $outputdir\ -Name "Privileges"
    }
}

# Collect email addresses
Function Get-EmailList() {
    ForEach ($email in $email_ignore_list) {
        $ignore_string += ".*$($email).*|"
    }
    $ignore_string = $ignore_string.TrimEnd('|')

    $emails = Get-ADUser -Filter * -Properties * `
        | Where { $_.Enabled -eq $True -and $_.Mail -ne $null -and ($_.LastLogonDate -gt (Get-Date).AddDays(-180)) } `
        | Select GivenName, Surname, Name, SAMAccountName, Mail, LastLogonDate `

        if ($email_ignore_list) {
            $emails = $emails | Where {$_.Mail -notmatch $ignore_string}
        }

        $emails | Export-CSV "$outputdir\Email\email_list.csv" -NoTypeInformation
        Write-Both $(Get-Date) '- Returned email addresses'
}

Function Get-InactiveUsers() {
    Get-ADUser -Filter * -Properties * `
        | Where { $_.Enabled -eq $True -and ($_.LastLogonDate -lt (Get-Date).AddDays(-30)) } `
        | Select GivenName, Surname, Name, SAMAccountName, LastLogonDate `
        | Export-CSV "$outputdir\Accounts\inactive_accounts.csv" -NoTypeInformation
    Write-Both $(Get-Date) '- Returned inactive accounts'
}

Function Get-UsersGroups() {
    $user_list = Get-ADUser -Filter * -Properties * | Where {$_.Enabled -eq $True}
    $disabled_user_list = Get-ADUser -Filter * -Properties * | Where {$_.Enabled -eq $False} 
    $user_array = New-Object System.Collections.ArrayList
    $disabled_user_array = New-Object System.Collections.ArrayList
    
    # Enabled Users
    ForEach ($user in $user_list) {
        $users_groups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName | Select -ExpandProperty Name
        [string]$users_groups_str = $users_groups -join ", "
        $user_object = New-Object System.Object
        $user_object | Add-Member -MemberType NoteProperty -Name "Username" -Value $user.SamAccountName
        $user_object | Add-Member -MemberType NoteProperty -Name "Groups" -Value $users_groups_str
        $user_array.Add($user_object) | Out-Null
    }
    $user_array | Export-Csv "$outputdir\Privileges\account_groups.csv" -NoTypeInformation

    # Disabled Users
    ForEach ($user in $disabled_user_list) {
        $users_groups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName | Select -ExpandProperty Name
        [string]$users_groups_str = $users_groups -join ", "
        $user_object = New-Object System.Object
        $user_object | Add-Member -MemberType NoteProperty -Name "Username" -Value $user.SamAccountName
        $user_object | Add-Member -MemberType NoteProperty -Name "Groups" -Value $users_groups_str
        $disabled_user_array.Add($user_object) | Out-Null
    }
    $disabled_user_array | Export-Csv "$outputdir\Privileges\disabled_account_groups.csv" -NoTypeInformation
    Write-Both $(Get-Date) '- Returned enabled and disabled users groups'
}

Function Get-PwdIssues() {
    $user_list = Get-ADUser -Filter * -Properties * | Where {$_.Enabled -eq $True -and $_.PasswordNeverExpires -eq $True -or $_.PasswordNotRequired -eq $True} `
        | Select GivenName, Surname, Name, SAMAccountName, LastLogonDate, PasswordNeverExpires, PasswordNotRequired `
        | Export-CSV "$outputdir\Accounts\password_issues.csv" -NoTypeInformation
    Write-Both $(Get-Date) '- Returned accounts that have non-expiring passwords'
}

Function Write-Both(){
    Write-Host "$args"
    Add-Content -Path $outputdir\log-$(Get-Date -Format 'yyyy-MM-dd').txt -Value "$args"
}

Function Get-OrgUnitRights() {
    $OU_array = New-Object System.Collections.ArrayList
    $OUs = Get-ADOrganizationalUnit -Filter *
    $result = @()
    ForEach($OU In $OUs){
        $path = "AD:\" + $OU.DistinguishedName
        $ACLs = (Get-Acl -Path $path).Access
        ForEach($ACL in $ACLs){
            if ($ACL.IsInherited -eq $False){
                $Properties = @{
                    ACL = $ACL
                    OU = $OU.DistinguishedName
                    }
                $result += New-Object psobject -Property $Properties
            }
        }
    }

    ForEach ($acl In $result){
        $OU_object = New-Object System.Object
        $OU_object | Add-Member -MemberType NoteProperty -Name "OU" -Value $acl.OU
        $OU_object | Add-Member -MemberType NoteProperty -Name "IdentityReference" -Value $acl.ACL.IdentityReference
        $OU_object | Add-Member -MemberType NoteProperty -Name "ActiveDirectoryRights" -Value $acl.ACL.ActiveDirectoryRights
        $OU_object | Add-Member -MemberType NoteProperty -Name "AccessControlType" -Value $acl.ACL.AccessControlType
        $OU_array.Add($OU_object) | Out-Null
    }
    $OU_array | Export-CSV "$outputdir\Privileges\ou_rights.csv" -NoTypeInformation
}

Function Get-TrustedDelegationAccounts() {
    Get-ADUser -Filter * -Properties * | ? {$_.TrustedForDelegation -eq $True | Select SamAccountName, TrustedForDelegation} | Where { $_.Enabled -eq $True} `
        | Select GivenName, Surname, Name, SAMAccountName, LastLogonDate, TrustedForDelegation `
        | Export-CSV "$outputdir\Accounts\delegated_accounts.csv" -NoTypeInformation
}
# To Do   
# AD Replications this month 
Function Get-UserReplicationEvents() {
    $users = Get-ADUser -Filter * -Properties * | Where { $_.Enabled -eq $True}
    $this_month = Get-Date -Format "yyyy-MM"
    ForEach ($user in $users) {
        Get-AdReplicationAttributeMetadata -Object (Get-ADUser $user) -Server $DomainController -Properties *  -IncludeDeletedObjects –ShowAllLinkedValues | Where-Object {$_.LastOriginatingChangeTime -contains $this_month} `
        | Select -Property LastOriginatingChangeTime, AttributeName, AttributeValue, LastOriginatingChangeDirectoryServerIdentity, LastOriginatingChangeUsn, LastOriginatingDeleteTime, LocalChangeUsn, Object, Server, Version `
        | Sort-Object -Property LastOriginatingChangeTime `
        | Export-CSV "$outputdir\Accounts\replication_events.csv" -NoTypeInformation
    }
}
 
# Enumerate who can access a machine object



Get-EmailList
Get-InactiveUsers
Get-UsersGroups
Get-PwdIssues
Get-OrgUnitRights
Get-TrustedDelegationAccounts
#Get-UserReplicationEvents