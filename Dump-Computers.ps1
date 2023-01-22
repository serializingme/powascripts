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

        Perform forward DNS lookup to obtain the computers addresses.

    .PARAMETER QueryDates

        Adds the created and changed dates to each user found.

    .PARAMETER QueryShares

        Asks the target computer what shares it exposes (delays execution and
        it is quite noisy).

    .PARAMETER QuerySessions

        Asks the target computer what sessions it has (delays execution and
        it is quite noisy).

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
        Version: 1.0.5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [String]$DomainFile,
        [Parameter(Mandatory = $True)]
        [String]$ResultFile,
        [Parameter(Mandatory = $False)]
        [Switch]$QueryDates,
        [Parameter(Mandatory = $False)]
        [Switch]$DNSResolve,
        [Parameter(Mandatory = $False)]
        [Switch]$QueryShares,
        [Parameter(Mandatory = $False)]
        [Switch]$QuerySessions
    )

    $NetApi = @'
using System;
using System.Runtime.InteropServices;

public class NetApi
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct ShareInfo1
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string netName;
        [MarshalAs(UnmanagedType.U4)]
        public uint type;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string remark;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SesionInfo10
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string computerName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string userName;
        [MarshalAs(UnmanagedType.U4)]
        public uint time;
        [MarshalAs(UnmanagedType.U4)]
        public uint idleTime;
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U4)]
    public static extern uint NetShareEnum(
        [MarshalAs(UnmanagedType.LPWStr)]
        string serverName,
        [MarshalAs(UnmanagedType.U4)]
        uint level,
        ref IntPtr bufPtr,
        [MarshalAs(UnmanagedType.U4)]
        uint prefMaxLen,
        [MarshalAs(UnmanagedType.U4)]
        ref uint entriesRead,
        [MarshalAs(UnmanagedType.U4)]
        ref uint totalEntries,
        [MarshalAs(UnmanagedType.U4)]
        ref uint resumeHandle);

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U4)]
    public static extern uint NetSessionEnum(
        [MarshalAs(UnmanagedType.LPWStr)]
        string serverName,
        [MarshalAs(UnmanagedType.LPWStr)]
        string uncClientName,
        [MarshalAs(UnmanagedType.LPWStr)]
        string userName,
        [MarshalAs(UnmanagedType.U4)]
        uint level,
        ref IntPtr bufPtr,
        [MarshalAs(UnmanagedType.U4)]
        uint prefMaxLen,
        [MarshalAs(UnmanagedType.U4)]
        ref uint entriesRead,
        [MarshalAs(UnmanagedType.U4)]
        ref uint totalEntries,
        [MarshalAs(UnmanagedType.U4)]
        ref uint resumeHandle);

    [DllImport("netapi32.dll")]
    [return: MarshalAs(UnmanagedType.U4)]
    public static extern uint NetApiBufferFree(
        IntPtr buffer);
}
'@

    Add-Type -TypeDefinition $NetApi

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

    function Process-ComputerSession {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$Computer
        )

        [IntPtr]$SessionInfos = [IntPtr]::Zero;
        [IntPtr]$Current = [IntPtr]::Zero;
        [UInt32]$EntriesRead = 0;
        [UInt32]$TotalEntries = 0;
        [UInt32]$ResumeHandle = 0;

        [String]$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.ToLower()

        try {
            if ([NetApi]::NetSessionEnum($Computer.Name, $Null, $Null, 10, [ref]$SessionInfos, [UInt32]::MaxValue,
                    [ref]$EntriesRead, [ref]$TotalEntries, [ref]$ResumeHandle) -eq 0) {

                # Need to keep the original reference in order to free the buffer.
                $Current = $SessionInfos;

                if ($EntriesRead -eq 0)
                {
                    return
                }

                $ResultFileWriter.WriteStartElement('Sessions')

                for ([UInt32]$Index = 0; $Index -lt $EntriesRead; $Index++)
                {
                    [Netapi+SesionInfo10]$SessionInfo = [Runtime.InteropServices.Marshal]::PtrToStructure(
                                    $Current, [Netapi+SesionInfo10]);

                    [String]$UserName = $SessionInfo.userName.ToLower()

                    if ($CurrentUser.Contains($UserName)) {
                        continue
                    }

                    [String]$ComputerName = $SessionInfo.computerName.ToLower().Trim(@('\'))

                    Write-Verbose ('Found session from {0} at {1}' -f $UserName, $Computer.Name)

                    $ResultFileWriter.WriteStartElement('Session')
                    $ResultFileWriter.WriteAttributeString('Computer', $ComputerName)
                    $ResultFileWriter.WriteAttributeString('User', $UserName)
                    $ResultFileWriter.WriteAttributeString('Time', $SessionInfo.time)
                    $ResultFileWriter.WriteAttributeString('Idle', $SessionInfo.idleTime)
                    $ResultFileWriter.WriteEndElement()

                    $Current = [IntPtr]($Current.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Netapi+SesionInfo10]))
                }

                $ResultFileWriter.WriteEndElement()
            }
        }
        catch {
            Write-Error $_
        }
        finally {
            if (($SessionInfos -ne [IntPtr]::Zero) -and ([NetApi]::NetApiBufferFree($SessionInfos) -ne 0)) {
                Write-Warning 'Failed to release the buffer containing the session information'
            }
        }
    }

    function Process-ComputerShare {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$Computer
        )

        [IntPtr]$ShareInfos = [IntPtr]::Zero;
        [IntPtr]$Current = [IntPtr]::Zero;
        [UInt32]$EntriesRead = 0;
        [UInt32]$TotalEntries = 0;
        [UInt32]$ResumeHandle = 0;

        try {
            if ([NetApi]::NetShareEnum($Computer.Name, 1, [ref]$ShareInfos, [UInt32]::MaxValue,
                    [ref]$EntriesRead, [ref]$TotalEntries, [ref]$ResumeHandle) -eq 0) {

                # Need to keep the original reference in order to free the buffer.
                $Current = $ShareInfos;

                if ($EntriesRead -eq 0)
                {
                    return
                }

                $ResultFileWriter.WriteStartElement('Shares')

                for ([UInt32]$Index = 0; $Index -lt $EntriesRead; $Index++)
                {
                    [Netapi+ShareInfo1]$ShareInfo = [Runtime.InteropServices.Marshal]::PtrToStructure(
                                    $Current, [Netapi+ShareInfo1]);

                    Write-Verbose ('Found share {0} in {1}' -f $ShareInfo.netName.ToLower(), $Computer.Name)

                    $ResultFileWriter.WriteStartElement('Share')
                    $ResultFileWriter.WriteAttributeString('Name', $ShareInfo.netName.ToLower())
                    $ResultFileWriter.WriteAttributeString('Remark', $ShareInfo.remark)
                    $ResultFileWriter.WriteEndElement()

                    $Current = [IntPtr]($Current.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Netapi+ShareInfo1]))
                }

                $ResultFileWriter.WriteEndElement()
            }
        }
        catch {
            Write-Error $_
        }
        finally {
            if (($ShareInfos -ne [IntPtr]::Zero) -and ([NetApi]::NetApiBufferFree($ShareInfos) -ne 0)) {
                Write-Warning 'Failed to release the buffer containing the file shares information'
            }
        }
    }

    function Process-Computer {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [Collections.Hashtable]$Computer,
            [Bool]$DNSResolve,
            [Bool]$QueryShares,
            [Bool]$QuerySessions
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

        if (($QueryShares -eq $True) -or ($QuerySessions -eq $True)) {
            $Online = Test-Connection -ComputerName $Computer.Name -Count 1 -TimeToLive 10 -Quiet

            if ($Online -eq $True) {
                if ($QueryShares -eq $True) {
                    Process-ComputerShare -ResultFileWriter $ResultFileWriter -Computer $Computer
                }

                if ($QuerySessions -eq $True) {
                    Process-ComputerSession -ResultFileWriter $ResultFileWriter -Computer $Computer
                }
            }
            else {
                Write-Warning ('Computer {0} seems to be down' -f $Computer.Name)
            }
        }

        $ResultFileWriter.WriteEndElement()
    }

    function Process-Domain {
        param(
            [Xml.XmlWriter]$ResultFileWriter,
            [String]$DomainName,
            [String]$DomainDNS,
            [Bool]$QueryDates,
            [Bool]$DNSResolve,
            [Bool]$QueryShares,
            [Bool]$QuerySessions
        )

        Write-Verbose ('Obtaining computers in the {0} domain' -f $DomainName)

        [DirectoryServices.DirectoryEntry]$DomainRoot = $Null
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

            if ($QueryDates -eq $True) {
                $ComputerSearch.PropertiesToLoad.Add('whencreated') | Out-Null
                $ComputerSearch.PropertiesToLoad.Add('whenchanged') | Out-Null
            }

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
                if (Is-ValidProperty -Property $_.Properties.dnshostname) {
                    $Computer.Name = $_.Properties.dnshostname.Item(0).ToLower()
                }
                elseif (Is-ValidProperty -Property $_.Properties.cn) {
                    $Computer.Name = ('{0}.{1}' -f $_.Properties.cn.Item(0).ToLower(), $DomainDNS.ToLower())
                }
                elseif (Is-ValidProperty -Property $_.Properties.name) {
                    $Computer.Name = ('{0}.{1}' -f $_.Properties.name.Item(0).ToLower(), $DomainDNS.ToLower())
                }
                if (Is-ValidProperty -Property $_.Properties.objectsid) {
                    $Computer.Identifier = BinarySID-ToStringSID -ObjectSID $_.Properties.objectsid.Item(0)
                }
                else {
                    $Computer.Identifier = 'S-1-0-0'
                }
                if (Is-ValidProperty -Property $_.Properties.description) {
                    $Computer.Description = $_.Properties.description.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.distinguishedname) {
                    $Computer.DN = $_.Properties.distinguishedname.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.operatingsystem) {
                    $Computer.OSName = $_.Properties.operatingsystem.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.operatingsystemversion) {
                    $Computer.OSVersion = $_.Properties.operatingsystemversion.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.operatingsystemservicepack) {
                    $Computer.OSPatch = $_.Properties.operatingsystemservicepack.Item(0)
                }
                if ($_.Properties.memberof -ne $Null) {
                    foreach ($Item in $_.Properties.memberof) {
                        $Computer.MemberOf.Add($Item)
                    }
                }
                if (Is-ValidProperty -Property $_.Properties.whencreated) {
                    $Computer.Created = $_.Properties.whencreated.Item(0)
                }
                if (Is-ValidProperty -Property $_.Properties.whenchanged) {
                    $Computer.Changed = $_.Properties.whenchanged.Item(0)
                }

                Process-Computer -ResultFileWriter $ResultFileWriter -Computer $Computer `
                        -DNSResolve $DNSResolve -QueryShares $QueryShares -QuerySessions $QuerySessions

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
                        -DomainDNS $Domain.DNS -QueryDates $QueryDates -DNSResolve $DNSResolve `
                        -QueryShares $QueryShares -QuerySessions $QuerySessions

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
