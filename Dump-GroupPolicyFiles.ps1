function Dump-GroupPolicyFiles {
    <#
    .SYNOPSIS

        Dump all the GPOs files from Active Directory into a folder.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump all the Group Policies files from Active Directory into a folder.

        Subfolders will be created for each domain.

    .PARAMETER DomainFile

        File containing the list of domains.

    .PARAMETER ResultDirectory

        Directory where the files will be dumped.

    .LINK

        https://www.serializing.me/tags/active-directory/

    .EXAMPLE

        Dump-GroupPolicyFiles -DomainFile .\Domains.xml -$ResultDirectory .\GroupPoliciesFiles

    .NOTE

        Function: Dump-GroupPolicyFiles
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
        [String]$ResultDirectory
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

    function Process-Policy {
        param(
            [IO.DirectoryInfo]$ResultDirectoryInfo,
            [Collections.Hashtable]$Policy
        )

        if ([String]::IsNullOrEmpty($Policy.GUID) -or [String]::IsNullOrEmpty($Policy.Path)) {
            return
        }

        Get-ChildItem -Path $Policy.Path -Recurse | ForEach-Object {
            [String]$Destination = ('{2}\{0}{1}' -f $Policy.GUID, $_.FullName.SubString(
                    $Policy.Path.Length), $ResultDirectoryInfo.FullName)

            if ($_.Attributes -eq 'Directory') {
                New-Item -Path $Destination -ItemType Directory -Force | Out-Null
            }
            else {
                Copy-Item -Path $_.FullName -Destination $Destination -Force
            }

            Write-Verbose ('Copied {0}' -f $_.FullName)
        }
    }

    function Process-Domain {
        param(
            [IO.DirectoryInfo]$ResultDirectoryInfo,
            [String]$DomainName,
            [String]$DomainDNS
        )

        Write-Verbose ('Obtaining group policy files for the {0} domain' -f $DomainName)

        [DirectoryServices.DirectoryEntry]$DomainRoot = $Null
        [DirectoryServices.DirectorySearcher]$PolicySearch = $Null

        try {
            [IO.DirectoryInfo]$DomainDirectoryInfo = New-Object IO.DirectoryInfo @(
                    [System.IO.Path]::Combine($ResultDirectoryInfo.FullName, $DomainName) )

            if ($DomainDirectoryInfo.Exists -eq $False) {
                New-Item -Path $ResultDirectoryInfo.FullName -Name $DomainName `
                        -Type Directory | Out-Null
            }

            [DirectoryServices.SortOption]$Sort = New-Object DirectoryServices.SortOption('name',
                    [DirectoryServices.SortDirection]::Ascending);

            $DomainRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://{0}' -f $DomainName )

            # Search for all group policies that have a name (usually a GUID).
            $PolicySearch = New-Object DirectoryServices.DirectorySearcher @(
                    $DomainRoot, '(&(objectclass=grouppolicycontainer)(name=*)(gpcfilesyspath=*))' )
            $PolicySearch.PageSize = 500
            $PolicySearch.Sort = $Sort
            $PolicySearch.PropertiesToLoad.Add('name') | Out-Null
            $PolicySearch.PropertiesToLoad.Add('gpcfilesyspath') | Out-Null

            [Collections.Hashtable]$Policy = @{
                'GUID' = $Null;
                'Path' = $Null;
            }

            [Collections.ArrayList]$Policies = New-Object Collections.ArrayList

            $PolicySearch.FindAll() | ForEach-Object {
                if (($_.Properties.name -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.name.Item(0)))) {
                    $Policy.GUID = $_.Properties.name.Item(0).ToUpper()
                }
                if (($_.Properties.gpcfilesyspath -ne $Null) -and
                        (-not [String]::IsNullOrEmpty($_.Properties.gpcfilesyspath.Item(0)))) {
                    $Policy.Path = $_.Properties.gpcfilesyspath.Item(0)
                }

                Process-Policy -ResultDirectoryInfo $DomainDirectoryInfo  -Policy $Policy

                # Add the processed policy GUID so that the current applied
                # policies can be compared with the ones in the destination
                # folder.
                $Policies.Add($Policy.GUID) | Out-Null

                # Make sure the hastable properties are null since it is being
                # reused.
                $Policy.GUID = $Null
                $Policy.Path = $Null
            }

            Write-Verbose ('Processed {0} policies for domain {1}' -f $Policies.Count,
                    $DomainName)

            # Remove any folder of inexistent policies.
            Get-ChildItem -Path $DomainDirectoryInfo.FullName -Recurse -Filter 'gpt.ini' | ForEach-Object {
                if ($Policies.Contains($_.Directory.Name) -eq $False) {
                    Remove-Item -Path $_.Directory.FullName -Recurse -Force

                    Write-Verbose ('Deleted folder {0} for inexistent policy' -f $_.Directory.FullName)
                }
            }
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

    try {
        [IO.FileInfo]$DomainFileInfo = New-Object IO.FileInfo @( $DomainFile )

        if ($DomainFileInfo.Exists -eq $False) {
            Write-Error 'The file to read the domains from does not exist'
        }

        [IO.DirectoryInfo]$ResultDirectoryInfo = New-Object IO.DirectoryInfo @( $ResultDirectory )

        if ($ResultDirectoryInfo.Exists -eq $False) {
            New-Item -Path $ResultDirectoryInfo.FullName -Type Directory | Out-Null
        }

        # Instantiate the XML stream and reader.
        $DomainFileStream = New-Object IO.FileStream @( $DomainFileInfo.FullName,
                [IO.FileMode]::Open, [IO.FileAccess]::Read )

        [Xml.XmlReaderSettings]$DomainXmlSettings = New-Object Xml.XmlReaderSettings
        $DomainXmlSettings.IgnoreProcessingInstructions = $True
        $DomainXmlSettings.IgnoreComments = $True
        $DomainXmlSettings.ProhibitDtd = $True

        $DomainFileReader = [Xml.XmlReader]::Create($DomainFileStream, $DomainXmlSettings)

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

                Process-Domain -ResultDirectoryInfo $ResultDirectoryInfo  -DomainName $Domain.Name `
                        -DomainDNS $Domain.DNS
            }
            elseif ($DomainFileReader.Name -eq 'Domain') {
                # Since the hashtable holding the domain information is being
                # reused, make sure the entries are cleared for the next domain.
                $Domain.Name = $Null
                $Domain.DNS = $Null
            }
        }
    }
    finally {
        if ($DomainFileReader -ne $Null) {
            $DomainFileReader.Close()
        }
        if ($DomainFileStream -ne $Null) {
            $DomainFileStream.Close()
        }
    }
}
