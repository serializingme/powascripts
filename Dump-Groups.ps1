function Dump-Groups {
    <#
    .SYNOPSIS

        Dump all the groups from Active Directory.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump all the group from Active Directory.

    .PARAMETER DomainFile

        File containing the list of domains.

    .PARAMETER ResultFile

        File that will be written with the groups.

    .PARAMETER QueryDates

        Adds the created and changed dates to each user found.

    .LINK

        https://www.serializing.me/tags/active-directory/

    .EXAMPLE

        Dump-Groups -DomainFile .\Domains.xml -ResultFile .\Groups.xml

    .NOTE

        Function: Dump-Groups
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

    function Process-Group {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$Group
        )

        $ResultFileWriter.WriteStartElement('Group')

        if ($Group.Name -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Name', $Group.Name)
        }
        if ($Group.Identifier -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Identifier', $Group.Identifier)
        }
        if ($Group.Description -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Description', $Group.Description)
        }
        if ($Group.DN -ne $Null) {
            $ResultFileWriter.WriteAttributeString('DN', $Group.DN)
        }
        if ($Group.Created -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Created',
                    (Date-ToString -Date $Group.Created -InUTC $True))
        }
        if ($Group.Changed -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Changed',
                    (Date-ToString -Date $Group.Changed -InUTC $True))
        }

        foreach ($Item in $Group.MemberOf) {
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

        Write-Verbose ('Obtaining groups in the {0} domain' -f $DomainName)

        [DirectoryServices.DirectoryEntry]$DomainRoot = $Null
        [DirectoryServices.DirectorySearcher]$GroupSearch = $Null

        try {
            [DirectoryServices.SortOption]$Sort = New-Object DirectoryServices.SortOption('objectsid',
                    [DirectoryServices.SortDirection]::Ascending);

            $DomainRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://{0}' -f $DomainName )

            $GroupSearch = New-Object DirectoryServices.DirectorySearcher @(
                    $DomainRoot, '(samaccounttype=268435456)' )
            $GroupSearch.PageSize = 500
            $GroupSearch.Sort = $Sort
            $GroupSearch.PropertiesToLoad.Add('name') | Out-Null
            $GroupSearch.PropertiesToLoad.Add('cn') | Out-Null
            $GroupSearch.PropertiesToLoad.Add('samaccountname') | Out-Null
            $GroupSearch.PropertiesToLoad.Add('objectsid') | Out-Null
            $GroupSearch.PropertiesToLoad.Add('description') | Out-Null
            $GroupSearch.PropertiesToLoad.Add('distinguishedname') | Out-Null
            $GroupSearch.PropertiesToLoad.Add('memberof') | Out-Null

            if ($QueryDates -eq $True) {
                $GroupSearch.PropertiesToLoad.Add('whencreated') | Out-Null
                $GroupSearch.PropertiesToLoad.Add('whenchanged') | Out-Null
            }

            [Collections.Hashtable]$Group = @{
                'Name' = $Null;
                'Identifier' = $Null;
                'Description' = $Null;
                'DN' = $Null;
                'MemberOf' = New-Object Collections.Generic.List[String];
                'Created' = $Null;
                'Changed' = $Null;
            }

            $GroupSearch.FindAll() | ForEach-Object {
                if (Is-ValidProperty -Property $_.Properties.name) {
                    $Group.Name = $_.Properties.name.Item(0)
                }
                elseif (Is-ValidProperty -Property $_.Properties.samaccountname) {
                    $Group.Name = ('{0}' -f $_.Properties.samaccountname.Item(0))
                }
                elseif (Is-ValidProperty -Property $_.Properties.cn) {
                    $Group.Name = ('{0}' -f $_.Properties.cn.Item(0))
                }
                if (Is-ValidProperty -Property $_.Properties.objectsid) {
                    $Group.Identifier = BinarySID-ToStringSID -ObjectSID $_.Properties.objectsid.Item(0)
                }
                else {
                    $Group.Identifier = 'S-1-0-0'
                }
                if (Is-ValidProperty -Property $_.Properties.description) {
                    $Group.Description = $_.Properties.description.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.distinguishedname) {
                    $Group.DN = $_.Properties.distinguishedname.Item(0)
                }
                if ($_.Properties.memberof -ne $Null) {
                    foreach ($Item in ($_.Properties.memberof | Sort-Object)) {
                        $Group.MemberOf.Add($Item)
                    }
                }
                if (Is-ValidProperty -Property $_.Properties.whencreated) {
                    $Group.Created = $_.Properties.whencreated.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.whenchanged) {
                    $Group.Changed = $_.Properties.whenchanged.Item(0)
                }

                Process-Group -ResultFileWriter $ResultFileWriter -Group $Group

                # Make sure the hastable properties are null since it is being
                # reused.
                $Group.Name = $Null
                $Group.Identifier = $Null
                $Group.Description = $Null
                $Group.DN = $Null
                $Group.MemberOf.Clear()
                $Group.Created = $Null
                $Group.Changed = $Null
            }
        }
        catch {
            Write-Warning ('Failed to find groups for {0} ({1})' -f $DomainName, $DomainDNS)
        }
        finally {
            if ($GroupSearch -ne $Null) {
                $GroupSearch.Dispose()
            }
            if ($DomainRoot -ne $Null) {
                try {
                    $DomainRoot.Dispose()
                }
                catch {
                    Write-Warning 'Failed to dispose the domain root, probably because the server is not operational'
                }
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
