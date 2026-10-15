rule Suspicious_Process_Injection_APIs
{
    meta:
        description = "Detects strings associated with process injection"

    strings:
        $a = "VirtualAllocEx" ascii
        $b = "WriteProcessMemory" ascii
        $c = "CreateRemoteThread" ascii

    condition:
        2 of them
}