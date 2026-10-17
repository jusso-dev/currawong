// Currawong starter rules. Tags decide what the gateway does with a match:
// `malware` quarantines as malware, `suspicious` quarantines as active
// content, any other tag is recorded on the scan report for policy only.

rule Currawong_EICAR_Test_File : malware test
{
    meta:
        description = "EICAR anti-malware test file, to prove the YARA path end to end"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}
