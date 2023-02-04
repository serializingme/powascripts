function Dump-UserPhotos {
    <#
    .SYNOPSIS

        Dump all the users pictures from Active Directory into a folder.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump all the users pictures from Active Directory into a folder.

        Subfolders will be created for each domain.

    .PARAMETER DomainFile

        File containing the list of domains.

    .PARAMETER ResultDirectory

        Directory where the files will be dumped.

    .LINK

        https://www.serializing.me/tags/active-directory/

    .EXAMPLE

        Dump-UserPhotos -DomainFile .\Domains.xml -$ResultDirectory .\UserPhotos

    .NOTE

        Function: Dump-UserPhotos
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

    function BinarySID-ToStringSID {
        param(
            [Byte[]]$ObjectSID
        )

        return (New-Object Security.Principal.SecurityIdentifier @(
                $ObjectSID, 0)).Value
    }

    function Process-User {
        param(
            [IO.DirectoryInfo]$ResultDirectoryInfo,
            [Collections.Hashtable]$User
        )

        if ([String]::IsNullOrEmpty($User.Identifier) -or $User.Photo -eq $Null) {
            return
        }

        [IO.FileStream]$OutputStream = $null

        try {
            $OutputStream = New-Object -TypeName 'System.IO.FileStream' -ArgumentList @(
                    [System.IO.Path]::Combine($ResultDirectoryInfo.FullName, ("{0}.jpeg" -f $User.Identifier)),
                    [IO.FileMode]::Create,
                    [IO.FileAccess]::Write
            )

            $OutputStream.Write($User.Photo, 0, $User.Photo.Length)
        }
        finally {
            if ($OutputStream -ne $null) {
                $OutputStream.Dispose()
            }
        }
    }

    function Process-Domain {
        param(
            [IO.DirectoryInfo]$ResultDirectoryInfo,
            [String]$DomainName,
            [String]$DomainDNS
        )

        Write-Verbose ('Obtaining users in the {0} domain' -f $DomainName)

        [DirectoryServices.DirectoryEntry]$DomainRoot = $Null
        [DirectoryServices.DirectorySearcher]$UserSearch = $Null

        try {
            [IO.DirectoryInfo]$DomainDirectoryInfo = New-Object IO.DirectoryInfo @(
                    [System.IO.Path]::Combine($ResultDirectoryInfo.FullName, $DomainName) )

            if ($DomainDirectoryInfo.Exists -eq $False) {
                New-Item -Path $ResultDirectoryInfo.FullName -Name $DomainName -Type Directory | Out-Null
            }

            [DirectoryServices.SortOption]$Sort = New-Object DirectoryServices.SortOption('objectsid',
                    [DirectoryServices.SortDirection]::Ascending);

            $DomainRoot = New-Object DirectoryServices.DirectoryEntry @(
                    'LDAP://{0}' -f $DomainName )

            $UserSearch = New-Object DirectoryServices.DirectorySearcher @(
                    $DomainRoot, '(&(samaccounttype=805306368)(thumbnailPhoto=*))' )
            $UserSearch.PageSize = 500
            $UserSearch.Sort = $Sort
            $UserSearch.PropertiesToLoad.Add('objectsid') | Out-Null
            $UserSearch.PropertiesToLoad.Add('thumbnailPhoto') | Out-Null

            [Collections.Hashtable]$User = @{
                'Identifier' = $Null;
                'Photo' = $Null;
            }

            $UserSearch.FindAll() | ForEach-Object {
                if ($_.Properties.objectsid -ne $Null) {
                    $User.Identifier = BinarySID-ToStringSID -ObjectSID $_.Properties.objectsid.Item(0)
                }
                else {
                    $User.Identifier = 'S-1-0-0'
                }
                if (($_.Properties.thumbnailphoto -ne $Null) -and
                        ($_.Properties.thumbnailphoto.Item(0) -ne $Null)) {
                    $User.Photo = $_.Properties.thumbnailphoto.Item(0)
                }

                Process-User -ResultDirectoryInfo $DomainDirectoryInfo -User $User

                $User.Identifier = $Null
                $User.Photo = $Null
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

                Process-Domain -ResultDirectoryInfo $ResultDirectoryInfo -DomainName $Domain.Name `
                        -DomainDNS $Domain.DNS
            }
            elseif ($DomainFileReader.Name -eq 'Domain') {
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
