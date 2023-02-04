function Dump-GroupPolicies {
    <#
    .SYNOPSIS

        Dump all the GPOs from Active Directory.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump all the Group Policies from Active Directory.

    .PARAMETER DomainFile

        File containing the list of domains.

    .PARAMETER ResultFile

        File that will be written with the GPOs.

    .PARAMETER QueryDates

        Adds the created and changed dates to each user found.

    .LINK

        https://www.serializing.me/tags/active-directory/

    .EXAMPLE

        Dump-GroupPolicies -DomainFile .\Domains.xml -ResultFile .\GroupPolicies.xml

    .NOTE

        Function: Dump-GroupPolicies
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

    function Process-Policy {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$Policy
        )

        $ResultFileWriter.WriteStartElement('GroupPolicy')
        $ResultFileWriter.WriteAttributeString('GUID', $Policy.GUID)

        if ($Policy.Name -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Name', $Policy.Name)
        }
        if ($Policy.Path -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Path', $Policy.Path)
        }
        if ($Policy.Version -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Version', $Policy.Version)
        }
        if ($Policy.Created -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Created',
                    (Date-ToString -Date $Policy.Created -InUTC $True))
        }
        if ($Policy.Changed -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Changed',
                    (Date-ToString -Date $Policy.Changed -InUTC $True))
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

        Write-Verbose ('Obtaining group policies for the {0} domain' -f $DomainName)

        [DirectoryServices.DirectoryEntry]$DomainRoot = $Null
        [DirectoryServices.DirectorySearcher]$PolicySearch = $Null

        try {
            [DirectoryServices.SortOption]$Sort = New-Object DirectoryServices.SortOption('name',
                    [DirectoryServices.SortDirection]::Ascending);

            $DomainRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://{0}' -f $DomainName )

            # Search for all group policies that have a name (usually a GUID).
            $PolicySearch = New-Object DirectoryServices.DirectorySearcher @(
                    $DomainRoot, '(&(objectclass=grouppolicycontainer)(name=*))' )
            $PolicySearch.PageSize = 500
            $PolicySearch.Sort = $Sort
            $PolicySearch.PropertiesToLoad.Add('displayname') | Out-Null
            $PolicySearch.PropertiesToLoad.Add('name') | Out-Null
            $PolicySearch.PropertiesToLoad.Add('gpcfilesyspath') | Out-Null
            $PolicySearch.PropertiesToLoad.Add('versionnumber') | Out-Null

            if ($QueryDates -eq $True) {
                $PolicySearch.PropertiesToLoad.Add('whencreated') | Out-Null
                $PolicySearch.PropertiesToLoad.Add('whenchanged') | Out-Null
            }

            [Collections.Hashtable]$Policy = @{
                'Name' = $Null;
                'GUID' = $Null;
                'Path' = $Null;
                'Version' = $Null;
                'Created' = $Null;
                'Changed' = $Null;
            }

            [Collections.ArrayList]$Policies = New-Object Collections.ArrayList

            $PolicySearch.FindAll() | ForEach-Object {
                $Policy.GUID = $_.Properties.name.Item(0).ToUpper()

                if (Is-ValidProperty -Property $_.Properties.displayname) {
                    $Policy.Name = $_.Properties.displayname.Item(0).ToUpper()
                }
                if (Is-ValidProperty -Property $_.Properties.gpcfilesyspath) {
                    $Policy.Path = $_.Properties.gpcfilesyspath.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.versionnumber) {
                    $Policy.Version = $_.Properties.versionnumber.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.whencreated) {
                    $Policy.Created = $_.Properties.whencreated.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.whenchanged) {
                    $Policy.Changed = $_.Properties.whenchanged.Item(0)
                }

                Process-Policy -ResultFileWriter $ResultFileWriter -Policy $Policy

                # Add the processed policy GUID so that the current applied
                # policies can be compared with the ones in the destination
                # folder.
                $Policies.Add($Policy.GUID) | Out-Null

                # Make sure the hastable properties are null since it is being
                # reused.
                $Policy.Name = $Null
                $Policy.GUID = $Null
                $Policy.Path = $Null
                $Policy.Version = $Null
                $Policy.Created = $Null
                $Policy.Changed = $Null
            }

            Write-Verbose ('Processed {0} policies for domain {1}' -f $Policies.Count,
                    $DomainName)
        }
        catch {
            Write-Warning ('Failed to find group policies for {0} ({1})' -f $DomainName, $DomainDNS)
        }
        finally {
            if ($PolicySearch -ne $Null) {
                $PolicySearch.Dispose()
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
                # Since the hashtable holding the domain information is being
                # reused, make sure the entries are cleared for the next domain.
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
