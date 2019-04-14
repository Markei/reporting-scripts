# This script lists all the groups in a specified OU/DC
# Copyright Markei.nl
# License MIT

param
(
    [Parameter(Mandatory = $true)] [string] $ou #'OU=Groups,OU=Teachers,DC=markeicollege,DC=nl'
)

Import-Module ActiveDirectory

$groups = Get-ADGroup -Filter * -SearchBase $ou -Properties MemberOf

$exportList = New-Object System.Collections.ArrayList
ForEach ($group in $groups) {
    #"Exporting details of " + $group

    $memberOf = New-Object System.Collections.ArrayList
    ForEach ($parentGroup in $group.MemberOf) {
        $parentGroupObject = Get-ADGroup -Identity $parentGroup
        $memberOf.Add($parentGroupObject.name) | Out-Null
    }
    $memberOf.Sort()

    $row = New-Object System.Object
    $row | Add-Member -MemberType NoteProperty -Name 'SamAccountName' -Value $group.SamAccountName
    $row | Add-Member -MemberType NoteProperty -Name 'DistinguishedName' -Value $group.DistinguishedName
    $row | Add-Member -MemberType NoteProperty -Name 'Name' -Value $group.Name
    $row | Add-Member -MemberType NoteProperty -Name 'GroupMemberships' -Value $memberOf

    $exportList.Add($row) | Out-Null
}

$exportList | Sort-Object -Property SamAccountName | ConvertTo-Json
