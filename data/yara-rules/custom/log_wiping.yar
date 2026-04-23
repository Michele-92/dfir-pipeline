rule LogWiping_Indicator {
    meta:
        description = "Erkennt Log-Löschungs-Muster"
        author      = "DFIR Pipeline"
        severity    = "critical"
    strings:
        $s1 = "> /var/log"         ascii
        $s2 = "truncate -s 0"      ascii
        $s3 = "rm -f /var/log"     ascii
        $s4 = "echo \"\" > /var/log" ascii
        $s5 = "shred /var/log"     ascii
        $s6 = "cat /dev/null >"    ascii
    condition:
        any of them
}

rule HistoryWiping_Indicator {
    meta:
        description = "Erkennt Shell-History-Löschung"
        severity    = "high"
    strings:
        $s1 = "history -c"      ascii
        $s2 = "unset HISTFILE"  ascii nocase
        $s3 = "HISTSIZE=0"      ascii
        $s4 = "HISTFILESIZE=0"  ascii
        $s5 = "rm ~/.bash_history" ascii
        $s6 = "rm ~/.zsh_history"  ascii
    condition:
        any of them
}
