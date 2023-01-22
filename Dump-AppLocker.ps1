function Dump-AppLocker {
    <#
    .SYNOPSIS

        Dump the computer AppLocker policy to a XML file.

    .DESCRIPTION

        This cmdlet allows a normal user, without any special permissions, to
        dump the AppLocker policy from the registry to a XML file.

    .PARAMETER ResultFile

        Where to write the AppLocker policy.

    .LINK

        https://www.serializing.me/tags/applocker/

    .EXAMPLE

        Dump-AppLocker -ResultFile .\AppLocker.xml

    .NOTE

        Function: Dump-AppLocker
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

    function Process-PolicyRule {
        param(
            [Xml.XmlWriter]$XmlWriter,
            [String]$Path
        )

        Write-Verbose ('Processing policy rule in {0}' -f $Path)

        [IO.StringReader]$StringReader = $Null
        [Xml.XmlReader]$XmlReader = $Null

        try {
            $Property = Get-ItemProperty -Path ('Registry::{0}' -f $Path) -Name 'Value' `
                    -ErrorAction SilentlyContinue

            $StringReader = New-Object IO.StringReader @( $Property.Value )

            [Xml.XmlReaderSettings]$RuleXmlSettings = New-Object Xml.XmlReaderSettings
            $RuleXmlSettings.IgnoreProcessingInstructions = $True
            $RuleXmlSettings.IgnoreComments = $True
            $RuleXmlSettings.ProhibitDtd = $True

            $XmlReader = [Xml.XmlReader]::Create($StringReader, $RuleXmlSettings)
            $XmlWriter.WriteNode($XmlReader, $False)
        }
        finally {
            if ($XmlReader -ne $Null) {
                $XmlReader.Close()
            }
            if ($StringReader -ne $Null) {
                $StringReader.Close()
            }
        }
    }

    function Process-PolicyGroup {
        param(
            [Xml.XmlWriter]$XmlWriter,
            [String]$Path
        )

        Write-Verbose ('Processing policy group in {0}' -f $Path)

        Get-ChildItem -Path ('Registry::{0}' -f $Path) | ForEach-Object {
            Process-PolicyRule -XmlWriter $XmlWriter -Path $_.Name
        }
    }

    function Process-PolicyGroups {
        param(
            [Xml.XmlWriter]$XmlWriter
        )

        # Get AppLocker policy groups and process the rules.
        Get-ChildItem -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\SrpV2' | ForEach-Object {
            $XmlWriter.WriteStartElement('Group')
            $XmlWriter.WriteAttributeString('Name', $_.PSChildName)

            Process-PolicyGroup -XmlWriter $XmlWriter -Path $_.Name

            $XmlWriter.WriteEndElement()
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
        $ResultFileWriter.WriteStartElement('AppLocker')
        $ResultFileWriter.WriteAttributeString('Date', (Date-ToString -Date (Get-Date)))
        $ResultFileWriter.WriteAttributeString('Host', (Hostname))

        Process-PolicyGroups -XmlWriter $ResultFileWriter

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
