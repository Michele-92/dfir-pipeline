/*
   Linux-relevante YARA-Regeln — kuratierte Auswahl
   Quelle: community/ Regeln gefiltert auf Linux-Relevanz
   Kategorien: Webshells, Linux-Rootkits, Backdoors, Cryptominer
*/

rule Linux_Webshell_PHP_Generic
{
    meta:
        description = "Erkennt generische PHP-Webshells auf Linux-Systemen"
        severity    = "high"
    strings:
        $s1 = "eval(base64_decode" ascii
        $s2 = "system($_GET"       ascii
        $s3 = "passthru($_POST"    ascii
        $s4 = "shell_exec($_REQUEST" ascii
    condition:
        any of them
}

rule Linux_Backdoor_Reverse_Shell
{
    meta:
        description = "Erkennt Reverse-Shell-Patterns in Skripten"
        severity    = "critical"
    strings:
        $s1 = "/bin/bash -i >& /dev/tcp/" ascii
        $s2 = "bash -i >& /dev/tcp"       ascii
        $s3 = "nc -e /bin/sh"             ascii
        $s4 = "python -c 'import socket"  ascii
    condition:
        any of them
}

rule Linux_Rootkit_LDPreload
{
    meta:
        description = "Erkennt LD_PRELOAD-basierte Rootkit-Muster"
        severity    = "critical"
    strings:
        $s1 = "LD_PRELOAD" ascii
        $s2 = "/etc/ld.so.preload" ascii
        $s3 = "hide_pid"   ascii
        $s4 = "hook_"      ascii
    condition:
        2 of them
}

rule Linux_Cryptominer_XMRig
{
    meta:
        description = "Erkennt XMRig-Cryptominer auf Linux"
        severity    = "high"
    strings:
        $s1 = "stratum+tcp://"  ascii
        $s2 = "xmrig"           ascii
        $s3 = "monero"          ascii nocase
        $s4 = "--donate-level"  ascii
    condition:
        2 of them
}

rule Linux_SSH_Authorized_Keys_Manipulation
{
    meta:
        description = "Erkennt Manipulation von authorized_keys"
        severity    = "high"
    strings:
        $s1 = "authorized_keys" ascii
        $s2 = "ssh-rsa AAAA"    ascii
        $s3 = "echo" ascii
    condition:
        $s1 and ($s2 or $s3)
}
