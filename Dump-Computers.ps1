function Dump-Computers {
    <#
    .SYNOPSIS

        Dump all the computers registered in Active Directory.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump all the computers registered in Active Directory.

    .PARAMETER DomainFile

        File containing the list of Windows domains.

    .PARAMETER ResultFile

        File that will be written with the domain computers.

    .PARAMETER DNSResolve

        Perform reverse DNS lookup to obtain the computers addresses.

    .LINK

        https://www.serializing.me/tags/active-directory/

    .EXAMPLE 
 
        Dump-Computers -DomainFile .\Domains.xml -ResultFile .\Computers.xml

    .EXAMPLE 
 
        Dump-Computers -DomainFile .\Domains.xml -ResultFile .\Computers.xml -DNSResolve

    .NOTE

        Function: Dump-Computers
        Author: Duarte Silva (@serializingme)
        License: GPLv3
        Required Dependencies: None
        Optional Dependencies: None
        Version: 1.0.0
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [String]$DomainFile,
        [Parameter(Mandatory = $True)]
        [String]$ResultFile,
        [Parameter(Mandatory = $False)]
        [Switch]$DNSResolve
    )

    function Date-ToString {
        param(
            [DateTime]$Date,
            [Bool]$InUTC = $False
        )

        [String]$format = 'yyyy-MM-ddTHH:mm:ss.fffffffZ'

        if ($InUTC) {
            return $Date.ToString($format)
        }
        else {
            return $Date.ToUniversaltime().ToString($format)
        }
    }

    function BinarySID-ToStringSID {
        param(
            [Byte[]]$ObjectSID
        )

        return (New-Object Security.Principal.SecurityIdentifier @(
                $ObjectSID, 0)).Value
    }

    function Forward-Lookup {
        param(
            [String]$Hostname
        )

        [String[]]$Result = $Null

        try {
            [Net.IPHostEntry]$HostEntry = [Net.DNS]::GetHostEntry($Hostname)
            $Result = $HostEntry.AddressList
        }
        catch {
            Write-Verbose ('Failed to resolve {0}' -f $Hostname)
        }

        return $Result
    }

    function Process-Computer {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$Computer,
            [Bool]$DNSResolve
        )

        $ResultFileWriter.WriteStartElement('Computer')

        if (-not [String]::IsNullOrEmpty($Computer.Name)) {
            $ResultFileWriter.WriteAttributeString('Name', $Computer.Name)
        }
        if (-not [String]::IsNullOrEmpty($Computer.Identifier)) {
            $ResultFileWriter.WriteAttributeString('Identifier', $Computer.Identifier)
        }
        if (-not [String]::IsNullOrEmpty($Computer.Description)) {
            $ResultFileWriter.WriteAttributeString('Description', $Computer.Description)
        }
        if (-not [String]::IsNullOrEmpty($Computer.DN)) {
            $ResultFileWriter.WriteAttributeString('DN', $Computer.DN)
        }
        if ($Computer.Created -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Created',
                    (Date-ToString -Date $Computer.Created -InUTC $True))
        }
        if ($Computer.Changed -ne $Null) {
            $ResultFileWriter.WriteAttributeString('Changed',
                    (Date-ToString -Date $Computer.Changed -InUTC $True))
        }

        # Do not write the OS element if there aren't any OS information to
        # write.
        if ((-not [String]::IsNullOrEmpty($Computer.OSName)) -or
                (-not [String]::IsNullOrEmpty($Computer.OSVersion)) -or
                (-not [String]::IsNullOrEmpty($Computer.OSPatch))) {
            $ResultFileWriter.WriteStartElement('OS')

            if (-not [String]::IsNullOrEmpty($Computer.OSName)) {
                $ResultFileWriter.WriteAttributeString('Name', $Computer.OSName)
            }
            if (-not [String]::IsNullOrEmpty($Computer.OSVersion)) {
                $ResultFileWriter.WriteAttributeString('Version', $Computer.OSVersion)
            }
            if (-not [String]::IsNullOrEmpty($Computer.OSPatch)) {
                $ResultFileWriter.WriteAttributeString('Patch', $Computer.OSPatch)
            }

            $ResultFileWriter.WriteEndElement()
        }

        foreach ($Item in $Computer.MemberOf) {
            $ResultFileWriter.WriteStartElement('MemberOf')
            $ResultFileWriter.WriteAttributeString('DN', $Item)
            $ResultFileWriter.WriteEndElement()
        }

        if ($DNSResolve -eq $True) {
            # Get the addresses for the host.
            [String[]]$Addresses = Forward-Lookup -Hostname $Computer.Name

            if ($Addresses -ne $Null) {
                $ResultFileWriter.WriteStartElement('Addresses')

                foreach ($Address in ($Addresses | Sort-Object)) {
                    Write-Verbose ('Resolved {1} to {0}' -f $Address, $Computer.Name)

                    $ResultFileWriter.WriteStartElement('Address')
                    $ResultFileWriter.WriteAttributeString('Value', $Address)
                    $ResultFileWriter.WriteEndElement()
                }

                $ResultFileWriter.WriteEndElement()
            }
        }

        $ResultFileWriter.WriteEndElement()
    }

    function Process-Domain {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [String]$DomainName,
            [String]$DomainDNS,
            [Bool]$DNSResolve
        )

        Write-Verbose ('Obtaining computers in the {0} domain' -f $DomainName)

        [DirectoryServices.DirectoryEntry]$MainRoot = $Null
        [DirectoryServices.DirectorySearcher]$ComputerSearch = $Null

        try {
            [DirectoryServices.SortOption]$Sort = New-Object DirectoryServices.SortOption('objectsid',
                    [DirectoryServices.SortDirection]::Ascending);
        
            $DomainRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://{0}' -f $DomainName )

            $ComputerSearch = New-Object DirectoryServices.DirectorySearcher @(
                    $DomainRoot, '(samaccounttype=805306369)' )
            $ComputerSearch.PageSize = 500
            $ComputerSearch.Sort = $Sort
            $ComputerSearch.PropertiesToLoad.Add('dnshostname') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('cn') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('name') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('objectsid') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('description') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('distinguishedname') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('operatingsystem') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('operatingsystemversion') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('operatingsystemservicepack') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('memberof') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('whencreated') | Out-Null
            $ComputerSearch.PropertiesToLoad.Add('whenchanged') | Out-Null

            [Collections.Hashtable]$Computer = @{
                'Name' = $Null;
                'Identifier' = $Null;
                'Description' = $Null;
                'DN' = $Null;
                'OSName' = $Null;
                'OSVersion' = $Null;
                'OSPatch' = $Null;
                'MemberOf' = New-Object Collections.Generic.List[String];
                'Created' = $Null;
                'Changed' = $Null;
            }

            $ComputerSearch.FindAll() | ForEach-Object {
                # When the property is not null, we assume there is at least
                # one element in it.
                if (($_.Properties.dnshostname -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.dnshostname.Item(0)))) {
                    $Computer.Name = $_.Properties.dnshostname.Item(0).ToLower()
                }
                elseif (($_.Properties.cn -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.cn.Item(0)))) {
                    $Computer.Name = ('{0}.{1}' -f $_.Properties.cn.Item(0).ToLower(), $DomainDNS.ToLower())
                }
                elseif (($_.Properties.name -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.name.Item(0)))) {
                    $Computer.Name = ('{0}.{1}' -f $_.Properties.name.Item(0).ToLower(), $DomainDNS.ToLower())
                }
                if ($_.Properties.objectsid -ne $Null) {
                    $Computer.Identifier = BinarySID-ToStringSID -ObjectSID $_.Properties.objectsid.Item(0)
                }
                else {
                    $Computer.Identifier = 'S-1-0-0'
                }
                if (($_.Properties.description -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.description.Item(0)))) {
                    $Computer.Description = $_.Properties.description.Item(0)
                }
                if (($_.Properties.distinguishedname -ne $Null) -and
                        ($_.Properties.distinguishedname.Item(0) -ne $Null)) {
                    $Computer.DN = $_.Properties.distinguishedname.Item(0)
                }
                if (($_.Properties.operatingsystem -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.operatingsystem.Item(0)))) {
                    $Computer.OSName = $_.Properties.operatingsystem.Item(0)
                }
                if (($_.Properties.operatingsystemversion -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.operatingsystemversion.Item(0)))) {
                    $Computer.OSVersion = $_.Properties.operatingsystemversion.Item(0)
                }
                if (($_.Properties.operatingsystemservicepack -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.operatingsystemservicepack.Item(0)))) {
                    $Computer.OSPatch = $_.Properties.operatingsystemservicepack.Item(0)
                }
                if ($_.Properties.memberof -ne $Null) {
                    foreach ($Item in $_.Properties.memberof) {
                        $Computer.MemberOf.Add($Item)
                    }
                }
                if (($_.Properties.whencreated -ne $Null) -and
                        ($_.Properties.whencreated.Item(0) -ne $Null)) {
                    $Computer.Created = $_.Properties.whencreated.Item(0)
                }
                if (($_.Properties.whenchanged -ne $Null) -and
                        ($_.Properties.whenchanged.Item(0) -ne $Null)) {
                    $Computer.Changed = $_.Properties.whenchanged.Item(0)
                }

                Process-Computer -ResultFileWriter $ResultFileWriter -Computer $Computer `
                        -DNSResolve $DNSResolve

                $Computer.Name = $Null
                $Computer.Identifier = $Null
                $Computer.Description = $Null
                $Computer.OSName = $Null
                $Computer.OSVersion = $Null
                $Computer.OSPatch = $Null
                $Computer.DN = $Null
                $Computer.MemberOf.Clear()
                $Computer.Created = $Null
                $Computer.Changed = $Null
            }
        }
        catch {
            Write-Warning ('Failed to find computers for {0} ({1})' -f $DomainName, $DomainDNS)
        }
        finally {
            if ($ComputerSearch -ne $Null) {
                $ComputerSearch.Dispose()
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
                        -DomainDNS $Domain.DNS -DNSResolve $DNSResolve

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
