rule Timestomping_Indicator {
    meta:
        description = "Erkennt Timestomping-Tools und -Muster"
        author      = "DFIR Pipeline"
        severity    = "high"
    strings:
        $s1 = "SetFileTime"   ascii
        $s2 = "touch -t"      ascii
        $s3 = "timestomp"     ascii nocase
        $s4 = "NtSetInformationFile" ascii
        $s5 = "FileBasicInformation" ascii
    condition:
        any of them
}

rule Timestomping_PowerShell {
    meta:
        description = "PowerShell Timestomping via .CreationTime / .LastWriteTime"
        severity    = "high"
    strings:
        $s1 = ".CreationTime"   ascii wide
        $s2 = ".LastWriteTime"  ascii wide
        $s3 = ".LastAccessTime" ascii wide
    condition:
        2 of them
}
