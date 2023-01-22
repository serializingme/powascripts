function Dump-Users {
    <#
    .SYNOPSIS

        Dump all the users from Active Directory.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump all the group from Active Directory.

    .PARAMETER DomainFile

        File containing the list of domains.

    .PARAMETER ResultFile

        File that will be written with the users.

    .PARAMETER QueryDates

        Adds the created and changed dates to each user found.

    .LINK

        https://www.serializing.me/tags/active-directory/

    .EXAMPLE

        Dump-Users -DomainFile .\Domains.xml -ResultFile .\Users.xml

    .NOTE

        Function: Dump-Users
        Author: Duarte Silva (@serializingme)
        License: GPLv3
        Required Dependencies: None
        Optional Dependencies: None
        Version: 1.0.5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [String]$DomainFile,
        [Parameter(Mandatory = $True)]
        [String]$ResultFile,
        [Parameter(Mandatory = $False)]
        [Switch]$QueryDates
    )

    function Date-ToString {
        param(
            [DateTime]$Date,
            [Bool]$InUTC = $False
        )

        [String]$Format = 'yyyy-MM-ddTHH:mm:ss.fffffffZ'

        if ($InUTC) {
            return $Date.ToString($Format)
        }
        else {
            return $Date.ToUniversaltime().ToString($Format)
        }
    }

    function Is-ValidProperty {
        param(
            [DirectoryServices.ResultPropertyValueCollection]$Property
        )

        return ($Property -ne $Null) -and ($Property.Count -eq 1) -and
                (-not [String]::IsNullOrEmpty($Property.Item(0)))
    }

    function BinarySID-ToStringSID {
        param(
            [Byte[]]$ObjectSID
        )

        return (New-Object Security.Principal.SecurityIdentifier @(
                $ObjectSID, 0)).Value
    }

    function Process-User {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$User
        )

        $ResultFileWriter.WriteStartElement('User')

        if ($User.Name -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Name', $User.Name)
        }
        if ($User.Identifier -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Identifier', $User.Identifier)
        }
        if ($User.Description -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Description', $User.Description)
        }
        if ($User.DN -ne $Null) {
            $ResultFileWriter.WriteAttributeString('DN', $User.DN)
        }
        if ($User.Expires -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Expires',
                    (Date-ToString -Date ([DateTime]::FromFileTimeUTC($User.Expires)) -InUTC $True))
        }
        if ($User.Expired -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Expired', $User.Expired)
        }
        if ($User.Locked -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Locked', $User.Locked)
        }
        if ($User.Disabled -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Disabled', $User.Disabled)
        }
        if ($User.NoPasswordRequired -ne $Null) {
            $ResultFileWriter.WriteAttributeString('NoPasswordRequired', $User.NoPasswordRequired)
        }
        if ($User.CanChangePassword -ne $Null) {
            $ResultFileWriter.WriteAttributeString('CanChangePassword', $User.CanChangePassword)
        }
        if ($User.PasswordDoesntExpire -ne $Null) {
            $ResultFileWriter.WriteAttributeString('PasswordDoesntExpire', $User.PasswordDoesntExpire)
        }
        if ($User.ExpiredPassword -ne $Null) {
            $ResultFileWriter.WriteAttributeString('ExpiredPassword', $User.ExpiredPassword)
        }
        if ($User.PreAuthNotRequired -ne $Null) {
            $ResultFileWriter.WriteAttributeString('PreAuthNotRequired', $User.PreAuthNotRequired)
        }
        if ($User.Created -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Created',
                    (Date-ToString -Date $User.Created -InUTC $True))
        }
        if ($User.Changed -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Changed',
                    (Date-ToString -Date $User.Changed -InUTC $True))
        }

        foreach ($Item in $User.MemberOf) {
            $ResultFileWriter.WriteStartElement('MemberOf')
            $ResultFileWriter.WriteAttributeString('DN', $Item)
            $ResultFileWriter.WriteEndElement()
        }

        $ResultFileWriter.WriteEndElement()
    }

    function Process-Domain {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [String]$DomainName,
            [String]$DomainDNS,
            [Bool]$QueryDates
        )

        Write-Verbose ('Obtaining users in the {0} domain' -f $DomainName)

        [DirectoryServices.DirectoryEntry]$DomainRoot = $Null
        [DirectoryServices.DirectorySearcher]$UserSearch = $Null

        try {
            [DirectoryServices.SortOption]$Sort = New-Object DirectoryServices.SortOption('objectsid',
                    [DirectoryServices.SortDirection]::Ascending);

            $DomainRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://{0}' -f $DomainName )

            $UserSearch = New-Object DirectoryServices.DirectorySearcher @(
                    $DomainRoot, '(samaccounttype=805306368)' )
            $UserSearch.PageSize = 500
            $UserSearch.Sort = $Sort
            $UserSearch.PropertiesToLoad.Add('userprincipalname') | Out-Null
            $UserSearch.PropertiesToLoad.Add('objectsid') | Out-Null
            $UserSearch.PropertiesToLoad.Add('description') | Out-Null
            $UserSearch.PropertiesToLoad.Add('distinguishedname') | Out-Null
            $UserSearch.PropertiesToLoad.Add('useraccountcontrol') | Out-Null
            $UserSearch.PropertiesToLoad.Add('accountexpires') | Out-Null
            $UserSearch.PropertiesToLoad.Add('memberof') | Out-Null

            if ($QueryDates -eq $True) {
                $UserSearch.PropertiesToLoad.Add('whencreated') | Out-Null
                $UserSearch.PropertiesToLoad.Add('whenchanged') | Out-Null
            }

            [Collections.Hashtable]$User = @{
                'Name' = $Null;
                'Identifier' = $Null;
                'Description' = $Null;
                'DN' = $Null;
                'Disabled' = $Null;
                'Expires' = $Null;
                'Expired' = $Null;
                'Locked' = $Null;
                'NoPasswordRequired' = $Null;
                'CanChangePassword' = $Null;
                'PasswordDoesntExpire' = $Null;
                'ExpiredPassword' = $Null;
                'PreAuthNotRequired' = $Null;
                'MemberOf' = New-Object Collections.Generic.List[String];
                'Created' = $Null;
                'Changed' = $Null;
            }

            $UserSearch.FindAll() | ForEach-Object {
                if (Is-ValidProperty -Property $_.Properties.userprincipalname) {
                    $User.Name = $_.Properties.userprincipalname.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.objectsid) {
                    $User.Identifier = BinarySID-ToStringSID -ObjectSID $_.Properties.objectsid.Item(0)
                }
                else {
                    $User.Identifier = 'S-1-0-0'
                }
                if (Is-ValidProperty -Property $_.Properties.description) {
                    $User.Description = $_.Properties.description.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.distinguishedname) {
                    $User.DN = $_.Properties.distinguishedname.Item(0)
                }
                if ((Is-ValidProperty -Property $_.Properties.accountexpires) -and
                        ($_.Properties.accountexpires.Item(0) -ne 0x7FFFFFFFFFFFFFFF)) {
                    $User.Expires = $_.Properties.accountexpires.Item(0)
                    $User.Expired = ($User.Expires -le ((Get-Date).ToFileTimeUTC()))
                }
                if (Is-ValidProperty -Property $_.Properties.useraccountcontrol) {
                    [Int32]$userAccountControl = $_.Properties.useraccountcontrol.Item(0)

                    $User.Disabled = (($userAccountControl -band 0x00000002) -eq 0x00000002)
                    $User.Locked = (($userAccountControl -band 0x00000010) -eq 0x00000010)
                    $User.NoPasswordRequired = (($userAccountControl -band 0x00000020) -eq 0x00000020)
                    $User.CanChangePassword = (($userAccountControl -band 0x00000040) -ne 0x00000040)
                    $User.PasswordDoesntExpire = (($userAccountControl -band 0x00010000) -eq 0x00010000)
                    $User.ExpiredPassword = (($userAccountControl -band 0x00800000) -eq 0x00800000)
                    $User.PreAuthNotRequired = (($userAccountControl -band 0x00400000) -eq 0x00400000)
                }
                if ($_.Properties.memberof -ne $Null) {
                    foreach ($Item in ($_.Properties.memberof | Sort-Object)) {
                        $User.MemberOf.Add($Item)
                    }
                }
                if (Is-ValidProperty -Property $_.Properties.whencreated) {
                    $User.Created = $_.Properties.whencreated.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.whenchanged) {
                    $User.Changed = $_.Properties.whenchanged.Item(0)
                }

                Process-User -ResultFileWriter $ResultFileWriter -User $User

                $User.Name = $Null
                $User.Identifier = $Null
                $User.Description = $Null
                $User.Disabled = $Null
                $User.Expires = $Null
                $User.Expired = $Null
                $User.Locked = $Null
                $User.NoPasswordRequired = $Null
                $User.CanChangePassword = $Null
                $User.PasswordDoesntExpire = $Null
                $User.ExpiredPassword = $Null
                $User.DN = $Null
                $User.MemberOf.Clear()
                $User.Created = $Null
                $User.Changed = $Null
            }
        }
        catch {
            Write-Warning ('Failed to find users for {0} ({1})' -f $DomainName, $DomainDNS)
        }
        finally {
            if ($UserSearch -ne $Null) {
                $UserSearch.Dispose()
            }
            if ($DomainRoot -ne $Null) {
                $DomainRoot.Dispose()
            }
        }
    }

    [IO.FileStream]$DomainFileStream = $Null
    [Xml.XmlReader]$DomainFileReader = $Null
    [IO.FileStream]$ResultFileStream = $Null
    [Xml.XmlWriter]$ResultFileWriter = $Null

    try {
        [IO.FileInfo]$DomainFileInfo = New-Object IO.FileInfo @( $DomainFile )

        if ($DomainFileInfo.Exists -eq $False) {
            Write-Error 'The file to read the domains from does not exist'
        }

        [IO.FileInfo]$ResultFileInfo = New-Object IO.FileInfo @( $ResultFile )

        if ($ResultFileInfo.Exists -eq $True) {
            Write-Warning 'The file to save the scan results to exists and it will be overwritten'
        }

        # Instantiate the XML stream and reader.
        $DomainFileStream = New-Object IO.FileStream @( $DomainFileInfo.FullName,
                [IO.FileMode]::Open, [IO.FileAccess]::Read )

        [Xml.XmlReaderSettings]$DomainXmlSettings = New-Object Xml.XmlReaderSettings
        $DomainXmlSettings.IgnoreProcessingInstructions = $True
        $DomainXmlSettings.IgnoreComments = $True
        $DomainXmlSettings.ProhibitDtd = $True

        $DomainFileReader = [Xml.XmlReader]::Create($DomainFileStream, $DomainXmlSettings)

        # Instantiate the XML stream and writer.
        $ResultFileStream = New-Object IO.FileStream @( $ResultFileInfo.FullName,
                [IO.FileMode]::Create, [IO.FileAccess]::Write )

        [Xml.XmlWriterSettings]$ResultXmlSettings = New-Object Xml.XmlWriterSettings
        $ResultXmlSettings.Indent = $True

        $ResultFileWriter = [Xml.XmlWriter]::Create($ResultFileStream, $ResultXmlSettings)
        $ResultFileWriter.WriteStartElement('Domains')
        $ResultFileWriter.WriteStartElement('Start')
        $ResultFileWriter.WriteAttributeString('Time', (Date-ToString -Date (Get-Date)))
        $ResultFileWriter.WriteEndElement()

        [Collections.HashTable]$Domain = @{
            'Name' = $Null;
            'DNS' = $Null;
        }

        while ($DomainFileReader.Read()) {
            if ($DomainFileReader.IsStartElement()) {
                if (($DomainFileReader.Name -ne 'Domain') -and
                        ($DomainFileReader.Name -ne 'Trusted')) {
                    continue
                }

                while ($DomainFileReader.MoveToNextAttribute()) {
                    if ($DomainFileReader.Name -eq 'Name') {
                        $Domain.Name = $DomainFileReader.Value
                    }
                    elseif ($DomainFileReader.Name -eq 'DNS') {
                        $Domain.DNS = $DomainFileReader.Value
                    }
                }

                $DomainFileReader.MoveToElement() | Out-Null

                $ResultFileWriter.WriteStartElement('Domain')
                $ResultFileWriter.WriteAttributeString('Name', $Domain.Name)
                $ResultFileWriter.WriteAttributeString('DNS', $Domain.DNS)

                Process-Domain -ResultFileWriter $ResultFileWriter -DomainName $Domain.Name `
                        -DomainDNS $Domain.DNS -QueryDates $QueryDates

                $ResultFileWriter.WriteEndElement()
            }
            elseif ($DomainFileReader.Name -eq 'Domain') {
                $Domain.Name = $Null
                $Domain.DNS = $Null
            }
        }

        $ResultFileWriter.WriteStartElement('End')
        $ResultFileWriter.WriteAttributeString('Time', (Date-ToString -Date (Get-Date)))
        $ResultFileWriter.WriteEndElement()
    }
    finally {
        if ($ResultFileWriter -ne $Null) {
            $ResultFileWriter.Close()
        }
        if ($ResultFileStream -ne $Null) {
            $ResultFileStream.Close()
        }
        if ($DomainFileReader -ne $Null) {
            $DomainFileReader.Close()
        }
        if ($DomainFileStream -ne $Null) {
            $DomainFileStream.Close()
        }
    }
}
