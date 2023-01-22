function Dump-Domains {
    <#
    .SYNOPSIS

        Dump all the domains and trust relationships.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump all the domains and respective trust relationships.

    .PARAMETER ResultFile

        File that will be written with the domains.

    .PARAMETER QueryDates

        Adds the created and changed dates to each domain found.

    .PARAMETER DNSResolve

        Perform reverse DNS lookup to obtain the domain controllers addresses
        as well as forward DNS lookups to obtain the host names.

    .LINK

        https://www.serializing.me/tags/active-directory/

    .EXAMPLE

        Dump-Domains -DomainFile .\Domains.xml

    .NOTE

        Function: Dump-Domains
        Author: Duarte Silva (@serializingme)
        License: GPLv3
        Required Dependencies: None
        Optional Dependencies: None
        Version: 1.0.5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [String]$ResultFile,
        [Parameter(Mandatory = $False)]
        [Switch]$QueryDates,
        [Parameter(Mandatory = $False)]
        [Switch]$DNSResolve
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

    function Forward-Lookup {
        param(
            [String]$HostName
        )

        [String[]]$Result = $Null

        try {
            [Net.IPHostEntry]$HostEntry = [Net.DNS]::GetHostByName($HostName)
            $Result = $HostEntry.AddressList
        }
        catch {
            Write-Verbose ('Failed to forward lookup {0}' -f $HostName)
        }

        return $Result
    }

    function Reverse-Lookup {
        param(
            [String]$Address
        )

        [String[]]$Result = $Null

        try {
            [Net.IPHostEntry]$HostEntry = [Net.DNS]::GetHostByAddress($Address)
            $Result = $HostEntry.HostName
        }
        catch {
            Write-Verbose ('Failed to reverse lookup {0}' -f $Address)
        }

        return $Result
    }

    function Perform-DNSResolution {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [String]$Hostname
        )

        [String[]]$Addresses = Forward-Lookup -Hostname $Hostname

        if ($Addresses -ne $Null) {
            $ResultFileWriter.WriteStartElement('Addresses')

            foreach ($Address in ($Addresses | Sort-Object)) {
                $ResultFileWriter.WriteStartElement('Address')
                $ResultFileWriter.WriteAttributeString('Value', $Address)

                [String]$DCName = Reverse-Lookup -Address $Address

                if (-not [String]::IsNullOrEmpty($DCName)) {
                    $ResultFileWriter.WriteAttributeString('DNS', $DCName)

                    Write-Verbose ('Resolved {1} to {0} ({2})' -f $Address, $Hostname, $DCName)
                }
                else {
                    Write-Verbose ('Resolved {1} to {0}' -f $Address, $Hostname)
                }

                $ResultFileWriter.WriteEndElement()
            }

            $ResultFileWriter.WriteEndElement()
        }
    }

    function Process-Trusted {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$Trusted,
            [Bool]$DNSResolve
        )

        $ResultFileWriter.WriteStartElement('Trusted')

        if (-not [String]::IsNullOrEmpty($Trusted.Name)) {
            $ResultFileWriter.WriteAttributeString('Name', $Trusted.Name)
        }
        if (-not [String]::IsNullOrEmpty($Trusted.DNS)) {
            $ResultFileWriter.WriteAttributeString('DNS', $Trusted.DNS)
        }

        # Peform the DNS resolution if needed.
        if ($DNSResolve -eq $True) {
            if ($Trusted.DNS -ne $Null) {
                Perform-DNSResolution -ResultFileWriter $ResultFileWriter -Hostname $Trusted.DNS
            }
            else {
                Write-Warning 'Unable to perform DNS resolution since the trusted domain does not have a DNS'
            }
        }

        $ResultFileWriter.WriteEndElement()
    }

    function Process-Domain {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$Domain,
            [Bool]$DNSResolve
        )

        Write-Verbose ('Processing domain {0}' -f $Domain.Name)

        [DirectoryServices.DirectoryEntry]$DomainRoot = $Null
        [DirectoryServices.DirectorySearcher]$RelatedSearch = $Null

        try {
            $ResultFileWriter.WriteStartElement('Domain')
            $ResultFileWriter.WriteAttributeString('Name', $Domain.Name)

            if ($Domain.DNS -ne $Null) {
                $ResultFileWriter.WriteAttributeString('DNS', $Domain.DNS)
            }
            if ($Domain.Created -ne $Null) {
                $ResultFileWriter.WriteAttributeString('Created',
                        (Date-ToString -Date $Domain.Created -InUTC $True))
            }
            if ($Domain.Changed -ne $Null) {
                $ResultFileWriter.WriteAttributeString('Changed',
                        (Date-ToString -Date $Domain.Changed -InUTC $True))
            }

            # Peform the DNS resolution if needed.
            if ($DNSResolve -eq $True) {
                if ($Domain.DNS -ne $Null) {
                    Perform-DNSResolution -ResultFileWriter $ResultFileWriter -Hostname $Domain.DNS
                }
                else {
                    Write-Warning 'Unable to perform DNS resolution since the domain does not have a DNS'
                }
            }

            # Get the domain trust relationships.
            $DomainRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://{0}' -f $Domain.Name )

            $RelatedSearch = New-Object DirectoryServices.DirectorySearcher @(
                    $DomainRoot, '(objectclass=trusteddomain)' )
            $RelatedSearch.PageSize = 500
            $RelatedSearch.PropertiesToLoad.Add('flatname') | Out-Null
            $RelatedSearch.PropertiesToLoad.Add('name') | Out-Null

            [Collections.Hashtable]$Trusted = @{
                'Name' = $Null;
                'DNS' = $Null;
            }

            $RelatedSearch.FindAll() | ForEach-Object {
                if (Is-ValidProperty -Property $_.Properties.flatname) {
                    $Trusted.Name = $_.Properties.flatname.Item(0).ToUpper()
                }
                if (Is-ValidProperty -Property $_.Properties.name) {
                    $Trusted.DNS = $_.Properties.name.Item(0).ToLower()
                }

                Process-Trusted -ResultFileWriter $ResultFileWriter -Trusted $Trusted -DNSResolve $DNSResolve

                # Make sure the hastable properties are null since it is being
                # reused.
                $Trusted.Name = $Null
                $Trusted.DNS = $Null
            }

            $ResultFileWriter.WriteEndElement()
        }
        catch {
            Write-Warning ('Failed to process domain {0} ({1})' -f $DomainName, $DomainDNS)
        }
        finally {
            if ($RelatedSearch -ne $Null) {
                $RelatedSearch.Dispose()
            }
            if ($DomainRoot -ne $Null) {
                $DomainRoot.Dispose()
            }
        }
    }

    function Process-Domains {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Bool]$QueryDates,
            [Bool]$DNSResolve
        )

        [DirectoryServices.DirectoryEntry]$MainRoot = $Null
        [DirectoryServices.DirectoryEntry]$PartitionsRoot = $Null
        [DirectoryServices.DirectorySearcher]$DomainSearch = $Null

        try {
            $MainRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://RootDSE' )

            $PartitionsRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://CN=Partitions,{0}' -f $MainRoot.Get('configurationNamingContext') )

            $DomainSearch = New-Object DirectoryServices.DirectorySearcher @(
                    $PartitionsRoot, '(&(objectcategory=crossref)(netbiosname=*))' )
            $DomainSearch.PageSize = 500
            $DomainSearch.PropertiesToLoad.Add('dnsroot') | Out-Null
            $DomainSearch.PropertiesToLoad.Add('ncname') | Out-Null
            $DomainSearch.PropertiesToLoad.Add('netbiosname') | Out-Null

            if ($QueryDates -eq $True) {
                $DomainSearch.PropertiesToLoad.Add('whencreated') | Out-Null
                $DomainSearch.PropertiesToLoad.Add('whenchanged') | Out-Null
            }

            [Collections.Hashtable]$Domain = @{
                'Name' = $Null;
                'DNS' = $Null;
                'Created' = $Null;
                'Changed' = $Null;
            }

            $DomainSearch.FindAll() | ForEach-Object {
                $Domain.Name = $_.Properties.netbiosname.Item(0)

                if (Is-ValidProperty -Property $_.Properties.dnsroot) {
                    $Domain.DNS = $_.Properties.dnsroot.Item(0).ToLower()
                }
                if (Is-ValidProperty -Property $_.Properties.whencreated) {
                    $Domain.Created = $_.Properties.whencreated.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.whenchanged) {
                    $Domain.Changed = $_.Properties.whenchanged.Item(0)
                }

                Process-Domain -ResultFileWriter $ResultFileWriter -Domain $Domain -DNSResolve $DNSResolve

                # Make sure the hastable properties are null since it is being
                # reused.
                $Domain.DNS = $Null
                $Domain.Created = $Null
                $Domain.Changed = $Null
            }
        }
        finally {
            if ($DomainSearch -ne $Null) {
                $DomainSearch.Dispose()
            }
            if ($PartitionsRoot -ne $Null) {
                $PartitionsRoot.Dispose()
            }
            if ($MainRoot -ne $Null) {
                $MainRoot.Dispose()
            }
        }
    }

    [IO.FileStream]$ResultFileStream = $Null
    [Xml.XmlWriter]$ResultFileWriter = $Null

    try {
        [IO.FileInfo]$ResultFileInfo = New-Object IO.FileInfo @( $ResultFile )

        if ($ResultFileInfo.Exists -eq $True) {
            Write-Warning 'The file to save the results already exists and it will be overwritten'
        }

        # Instantiate the XML stream and writer.
        $ResultFileStream = New-Object IO.FileStream -ArgumentList @(
                $ResultFileInfo.FullName, [IO.FileMode]::Create, [IO.FileAccess]::Write )

        [Xml.XmlWriterSettings]$ResultXmlSettings = New-Object Xml.XmlWriterSettings
        $ResultXmlSettings.Indent = $True

        $ResultFileWriter = [Xml.XmlWriter]::Create($ResultFileStream, $ResultXmlSettings)
        $ResultFileWriter.WriteStartElement('Domains')
        $ResultFileWriter.WriteStartElement('Start')
        $ResultFileWriter.WriteAttributeString('Time', (Date-ToString -Date (Get-Date)))
        $ResultFileWriter.WriteEndElement()

        Process-Domains -ResultFileWriter $ResultFileWriter -QueryDates $QueryDates -DNSResolve $DNSResolve

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
    }
}
