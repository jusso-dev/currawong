// Business email compromise signals. Tagged `bec`, so a match is recorded on
// the scan report for policy and does not quarantine on its own.

rule Currawong_Bank_Detail_Change : bec
{
    meta:
        description = "Asks to change bank details and quotes a BSB"
    strings:
        $ask1 = "change of bank details" nocase
        $ask2 = "updated bank details" nocase
        $ask3 = "new bank account" nocase
        $bsb = /BSB[: ]{0,3}[0-9]{3}-?[0-9]{3}/ nocase
    condition:
        any of ($ask*) and $bsb
}
