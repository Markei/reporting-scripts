# This script lists all the groups in a specified OU/DC
# Copyright Markei.nl

param
(
    [Parameter(Mandatory = $true)] [string] $ou #'OU=Users,OU=Teachers,DC=markeicollege,DC=nl'
)

Import-Module ActiveDirectory

$users = Get-ADUser -Filter * -SearchBase $ou

$exportList = New-Object System.Collections.ArrayList
ForEach ($user in $users) {
    #"Exporting details of " + $user.SamAccountName

    $groups = Get-ADPrincipalGroupMembership -Identity $user

    $memberOf = New-Object System.Collections.ArrayList
    ForEach ($group in $groups) {
        $memberOf.Add($group.name) | Out-Null
    }
    $memberOf.Sort()

    $row = New-Object System.Object
    $row | Add-Member -MemberType NoteProperty -Name 'SamAccountName' -Value $user.SamAccountName
    $row | Add-Member -MemberType NoteProperty -Name 'UserPrincipalName' -Value $user.UserPrincipalName
    $row | Add-Member -MemberType NoteProperty -Name 'GivenName' -Value $user.GivenName
    $row | Add-Member -MemberType NoteProperty -Name 'Surname' -Value $user.Surname
    $row | Add-Member -MemberType NoteProperty -Name 'Name' -Value $user.Name
    $row | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value $user.DistinguishedName
    $row | Add-Member -MemberType NoteProperty -Name 'Enabled' -Value $user.Enabled
    $row | Add-Member -MemberType NoteProperty -Name 'GroupMemberships' -Value $memberOf
    
    $exportList.Add($row) | Out-Null
}

$exportList | Sort-Object -Property SamAccountName | ConvertTo-Json
