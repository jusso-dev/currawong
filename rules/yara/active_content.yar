// Loaders that commonly arrive by email. Tagged `suspicious`, so a match is
// quarantined as active content.

rule Currawong_HTML_Smuggling : suspicious
{
    meta:
        description = "HTML that decodes a file in the browser and saves it"
    strings:
        $html = "<html" nocase
        $blob = "new Blob(" nocase
        $atob = "atob(" nocase
        $save1 = "msSaveOrOpenBlob" nocase
        $save2 = "createObjectURL" nocase
    condition:
        $html and $blob and $atob and any of ($save*)
}

rule Currawong_Encoded_PowerShell : suspicious
{
    meta:
        description = "PowerShell started with a base64 encoded command"
    strings:
        $ps = "powershell" nocase
        $enc = /\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/=]{40,}/ nocase
    condition:
        $ps and $enc
}

rule Currawong_Windows_Shortcut : suspicious
{
    meta:
        description = "Windows shortcut (.lnk) file"
    condition:
        uint32(0) == 0x0000004C and uint32(4) == 0x00021401
}
