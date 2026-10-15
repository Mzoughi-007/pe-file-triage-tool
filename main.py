import os
import pefile
import hashlib
import sys
import json
from pathlib import Path
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()
def extract_pe_metadata(file_path):
    pe = pefile.PE(file_path)

    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "sections_count": pe.FILE_HEADER.NumberOfSections,
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
    }
def extract_sections(file_path):
    pe = pefile.PE(file_path)
    sections = []

    for section in pe.sections:
        characteristics = section.Characteristics
        permissions = decode_permissions(characteristics)
        sections.append({
            "name": section.Name.decode(
                "utf-8", errors="replace"
            ).rstrip("\x00"),
            "virtual_size": section.Misc_VirtualSize,
            "raw_size": section.SizeOfRawData,
            "permissions": permissions,
            "suspicious_wx": permissions["write"] and permissions["execute"],
        })

    return sections
def extract_imports(file_path):
    pe = pefile.PE(file_path)
    imports = []

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode(errors="replace")

            for imp in entry.imports:
                name = (
                    imp.name.decode(errors="replace")
                    if imp.name else f"ordinal_{imp.ordinal}"
                )

                imports.append({
                    "dll": dll,
                    "function": name,
                })

    return imports
def find_suspicious_imports(imports):
    suspicious_apis = {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "VirtualProtectEx",
        "WinExec",
    }

    return [
        item for item in imports
        if item["function"].lower() in {
            api.lower() for api in suspicious_apis
        }
    ]

def decode_permissions(characteristics):
    return {
        "read": bool(characteristics & 0x40000000),
        "write": bool(characteristics & 0x80000000),
        "execute": bool(characteristics & 0x20000000),
    }

def check_digital_signature(file_path):
    import subprocess

    command = (
        "$sig = Get-AuthenticodeSignature "
        + "'" + file_path.replace("'", "''") + "'; "
        + "[PSCustomObject]@{"
        + "status = $sig.Status.ToString(); "
        + "status_message = $sig.StatusMessage; "
        + "signer = if ($sig.SignerCertificate) "
        + "{ $sig.SignerCertificate.Subject } else { $null }"
        + "} | ConvertTo-Json -Compress"
    )

    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )

        return json.loads(result.stdout)

    except (subprocess.SubprocessError, json.JSONDecodeError):
        return {
            "status": "CheckFailed",
            "status_message": "Could not check digital signature",
            "signer": None,
        }

def scan_with_yara(file_path):
    import subprocess

    command = [
        r"D:\Downloads\yara64.exe",
        str(Path("rules/basic_suspicious.yar").resolve()),
        str(Path(file_path).resolve()),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode not in (0, 1):
            return {"matches": [], "error": result.stderr.strip()}

        return {
            "matches": result.stdout.splitlines(),
            "error": None,
        }

    except (subprocess.SubprocessError, OSError) as exc:
        return {"matches": [], "error": str(exc)}

if __name__ == "__main__":
    file_path = input("Enter file path: ").strip().strip('"')
    if not os.path.isfile(file_path):
        print("Error: File not found.")
        sys.exit(1)

    signature = check_digital_signature(file_path)
    print("Digital Signature:")
    print(json.dumps(signature, indent=4))

    try:
        print("SHA-256:", calculate_sha256(file_path))
        print("File size:", os.path.getsize(file_path), "bytes")

        metadata = extract_pe_metadata(file_path)
        print("PE Metadata:")
        print(json.dumps(metadata, indent=4))

        sections = extract_sections(file_path)
        print("PE Sections:")
        print(json.dumps(sections, indent=4))

        imports = extract_imports(file_path)
        suspicious = find_suspicious_imports(imports)
        yara_result = scan_with_yara(file_path)
        if yara_result["error"]:
            print("YARA error:", yara_result["error"])

        wx_sections = [
            section["name"]
            for section in sections
            if section["suspicious_wx"]
        ]

        warnings = []
        risk_reasons = []

        if yara_result["matches"]:
            warnings.append("YARA rule match detected")
            risk_reasons.append(
                f"YARA matched: {', '.join(yara_result['matches'])}"
            )

        if suspicious:
            warnings.append("Suspicious API imports detected")
            risk_reasons.append(
                  f"Found {len(suspicious)} suspicious API import(s)"
            )

        if wx_sections:
            warnings.append("Writable and executable sections detected")
            risk_reasons.append(
                  f"Writable and executable sections: {', '.join(wx_sections)}"
        )


        common_sections = {
            ".text", ".data", ".rdata", ".bss",
            ".idata", ".edata", ".rsrc", ".reloc",
            ".pdata", ".xdata", ".tls", ".didat",
        }

        unusual_sections = [
            section["name"]
            for section in sections
            if section["name"].lower() not in common_sections
        ]

        if unusual_sections:
            warnings.append("Unusual section names detected")
            risk_reasons.append(
                  f"Unusual section names (not necessarily malicious): "
                  f"{', '.join(unusual_sections)}"
        )

        risk_level = "Low"

        if suspicious or wx_sections or yara_result["matches"]:
            risk_level = "High"
        elif unusual_sections:
            risk_level = "Medium"

        report = {
            "sha256": calculate_sha256(file_path),
            "file_size": os.path.getsize(file_path), 
            "metadata": metadata,
            "sections": sections,
            "suspicious_imports": suspicious,
            "imports": imports,
            "warnings": warnings,
            "unusual_sections": unusual_sections,
            "risk_level": risk_level,
            "risk_reasons": risk_reasons,
            "digital_signature": signature,
            "yara_matches": yara_result["matches"],
            "yara_error": yara_result["error"],
        }

        report_path = Path(file_path).name + ".report.json"

        print("Risk Level:", risk_level)


        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        print(f"Report saved to {report_path}")
        print("Suspicious Imports:")
        print(json.dumps(suspicious, indent=4))

    except pefile.PEFormatError:
        print("Error: This file is not a valid PE file.")