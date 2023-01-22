function Dump-PowerBroker {
    <#
    .SYNOPSIS

        Dump the PowerBroker policy to a XML file.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump the BeyondTrust's PowerBroker policy from the registry to a XML
        file.

    .PARAMETER ResultFile

        Where to write the PowerBroker policy.

    .LINK

        https://www.serializing.me/tags/powerbroker/

    .EXAMPLE

        Dump-PowerBroker -ResultFile .\PowerBroker.xml

    .NOTE

        Function: Dump-PowerBroker
        Author: Duarte Silva (@serializingme)
        License: GPLv3
        Required Dependencies: None
        Optional Dependencies: None
        Version: 1.0.5
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)]
        [String]$ResultFile
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

    function StringSID-ToStringName {
        param(
            [String]$ObjectSID
        )

        return (New-Object Security.Principal.SecurityIdentifier @(
                $ObjectSID)).Translate([System.Security.Principal.NTAccount]).ToString()
    }

    function Process-UserRuleOptions {
        param(
            [Xml.XmlWriter]$XmlWriter,
            $Rule
        )

        [String[]]$Options = @(
            'Program', 'Authenticate', 'Action', 'DropDialogRights', 'EnableNetworkStatus',
            'DisableUNCTranslation', 'ArgumentsExactMatch', 'BlockInheritance', 'Recursive'
        )

        foreach ($Option in $Options)
        {
            $Value = $Rule.GetValue($Option)

            if ($Value -eq $Null)
            {
                continue
            }

            $XmlWriter.WriteStartElement('Option')
            $XmlWriter.WriteAttributeString('Name', $Option)
            $XmlWriter.WriteAttributeString('Value', $Value)
            $XmlWriter.WriteEndElement()
        }
    }

    function Process-UserRule {
        param(
            [Xml.XmlWriter]$XmlWriter,
            [String]$Identifier,
            [String]$Path
        )

        Write-Verbose ('Processing user rule in {0}' -f $Path)

        $Rule = Get-Item -Path ('Registry::{0}' -f $Path)

        $XmlWriter.WriteStartElement('Rule')
        $XmlWriter.WriteAttributeString('Identifier', $Identifier)
        $XmlWriter.WriteAttributeString('Name', $Rule.GetValue(''))
        $XmlWriter.WriteAttributeString('Order', $Rule.GetValue('order'))
        $XmlWriter.WriteAttributeString('Type', $Rule.GetValue('type'))

        $XmlWriter.WriteStartElement('GPO')
        $XmlWriter.WriteAttributeString('Type', $Rule.GetValue('gpo'))
        $XmlWriter.WriteAttributeString('GUID', $Rule.GetValue('gpoguid'))
        $XmlWriter.WriteAttributeString('Name', $Rule.GetValue('gponame'))
        $XmlWriter.WriteEndElement()

        $XmlWriter.WriteStartElement('Options')

        Process-UserRuleOptions -XmlWriter $XmlWriter -Rule $Rule

        $XmlWriter.WriteEndElement()

        $XmlWriter.WriteStartElement('Permissions')

        Get-ChildItem -Path ('Registry::{0}\Permissions' -f $Path) -ErrorAction SilentlyContinue | ForEach-Object {
            $XmlWriter.WriteStartElement('Permission')
            $XmlWriter.WriteAttributeString('Identifier', $_.PSChildName)

            $Name = (Get-Item -Path ('Registry::{0}' -f $_.Name)).GetValue('')

            if ($Name -ne $Null) {
                $XmlWriter.WriteAttributeString('Name', $Name)
            }

            $XmlWriter.WriteEndElement()
        }

        $XmlWriter.WriteEndElement()

        $XmlWriter.WriteStartElement('Privileges')

        Get-ChildItem -Path ('Registry::{0}\Privileges' -f $Path) -ErrorAction SilentlyContinue | ForEach-Object {
            $XmlWriter.WriteStartElement('Privilege')
            $XmlWriter.WriteAttributeString('Type', $_.PSChildName)
            $XmlWriter.WriteEndElement()
        }

        $XmlWriter.WriteEndElement()
        $XmlWriter.WriteEndElement()
    }

    function Process-UserRules {
        param(
            [Xml.XmlWriter]$XmlWriter,
            [String]$Identifier,
            [String]$Path
        )

        Write-Verbose ('Processing user policy in {0}' -f $Path)

        $XmlWriter.WriteStartElement('User')
        $XmlWriter.WriteAttributeString('Identifier', $Identifier)
        $XmlWriter.WriteAttributeString('Name', (StringSID-ToStringName $Identifier))

        Get-ChildItem -Path ('Registry::{0}' -f $Path) | ForEach-Object {
            Process-UserRule -XmlWriter $XmlWriter -Identifier $_.PSChildName -Path $_.Name
        }

        $XmlWriter.WriteEndElement()
    }

    function Process-PolicyRules {
        param(
            [Xml.XmlWriter]$XmlWriter
        )

        Get-ChildItem -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\BeyondTrust\SD\Applications\Rules\Users' | ForEach-Object {
            Process-UserRules -XmlWriter $XmlWriter -Identifier $_.PSChildName -Path $_.Name
        }
    }

    [IO.FileStream]$ResultFileStream = $Null
    [Xml.XmlWriter]$ResultFileWriter = $Null

    try {
        [IO.FileInfo]$ResultFileInfo = New-Object IO.FileInfo @( $ResultFile )

        if ($ResultFileInfo.Exists) {
            $PSCmdlet.WriteWarning('The selected file for the policy exists and it will be overwritten')
        }

        # Instantiate the streams.
        $ResultFileStream = New-Object IO.FileStream @( $ResultFileInfo.FullName,
                [IO.FileMode]::Create, [IO.FileAccess]::Write )

        [Xml.XmlWriterSettings]$ResultXmlSettings = New-Object Xml.XmlWriterSettings
        $ResultXmlSettings.Indent = $True

        # Instantiate the XML writer.
        $ResultFileWriter = [Xml.XmlWriter]::Create($ResultFileStream, $ResultXmlSettings)
        $ResultFileWriter.WriteStartElement('PowerBroker')
        $ResultFileWriter.WriteAttributeString('Date', (Date-ToString -Date (Get-Date)))
        $ResultFileWriter.WriteAttributeString('Host', (Hostname))

        Process-PolicyRules -XmlWriter $ResultFileWriter

        $ResultFileWriter.WriteEndElement()
    }
    finally {
        if ($ResultFileWriter -ne $Null) {
            $ResultFileWriter.Close()
        }
        if ($ResultFileStream -ne $Null) {
            $ResultFileStream.Dispose()
        }
    }
}
