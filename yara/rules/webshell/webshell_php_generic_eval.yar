rule Webshell_PHP_Generic_Eval
{
    meta:
        description = "Detects PHP webshells passing request data directly into a code execution function"
        author = "bb-chani"
        date = "2026-09-15"
        reference = "https://attack.mitre.org/techniques/T1505/003/"
        severity = "high"

    strings:
        $php_open = "<?php" ascii nocase

        $exec_eval   = "eval(" ascii nocase
        $exec_assert = "assert(" ascii nocase
        $exec_system = "system(" ascii nocase
        $exec_shell  = "shell_exec(" ascii nocase
        $exec_passth = "passthru(" ascii nocase

        $src_get     = "$_GET[" ascii
        $src_post    = "$_POST[" ascii
        $src_request = "$_REQUEST[" ascii
        $src_cookie  = "$_COOKIE[" ascii

    condition:
        filesize < 200KB
        and $php_open
        and any of ($exec_*)
        and any of ($src_*)
}
