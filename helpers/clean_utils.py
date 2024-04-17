import os
import time
import configparser

from helpers.ldap_utils import unset_attribute, modify_attribute
from conf import CLEAN_DIR, bcolors

def init_save_file(OU_name):
    os.makedirs(os.path.join(CLEAN_DIR, OU_name), exist_ok=True)

    timestr = time.strftime("%Y_%m_%d-%H_%M_%S")
    save_file_name = os.path.join(CLEAN_DIR, OU_name, timestr + ".txt")

    open(save_file_name, "x")
    return save_file_name

def save_attribute_value(attribute_name, value, save_file, target, dn):
    with open(save_file, 'a') as f:
        to_write = f"[{attribute_name}]\ndn={dn}\ntarget={target}\nold_value={value}\n\n"
        f.write(to_write)

def clean(domain_ldap_session, ldap_server_ldap_session, save_file):
    to_clean = configparser.ConfigParser()
    to_clean.read(save_file)

    for key in to_clean:
        if key == "DEFAULT":
            continue
        if to_clean[key]['target'] == "domain":
            session = domain_ldap_session
        else:
            session = ldap_server_ldap_session
        dn = to_clean[key]['dn']

        if 'old_value' not in to_clean[key]:
            print(f"{bcolors.FAIL}[-] No old value saved for {key}. Skipping.{bcolors.ENDC}")
            continue
        if session == None:
            print(f"{bcolors.FAIL}[-] No session to restore {key}. Skipping.{bcolors.ENDC}")
            continue
        print(f"[*] Restoring value of {key} on '{to_clean[key]['target']}' - {to_clean[key]['old_value']}")
        if to_clean[key]['old_value'] == '[]' or to_clean[key]['old_value'] == '' or to_clean[key]['old_value'] == 'None':
            result = unset_attribute(session, dn, key)
        else:
            result = modify_attribute(session, dn, key, to_clean[key]['old_value'])
        
        if result is True:
            print(f"{bcolors.OKGREEN}[+] Successfully restored {key} on '{to_clean[key]['target']}'{bcolors.ENDC}")
        else:
            print(f"{bcolors.FAIL}[-] Couldn't clean value for {key} on '{to_clean[key]['target']}'. You can try to re-run OUned with the {bcolors.ENDC}{bcolors.BOLD}--just-clean{bcolors.ENDC} flag, or clean LDAP attributes manually{bcolors.ENDC}")