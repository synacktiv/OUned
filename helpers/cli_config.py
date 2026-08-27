import configparser
import uuid
import typer
from dataclasses import dataclass
from typing import Optional, List
from helpers.utils import logger

@dataclass
class Config:
    ou_dn: str
    domain: str
    dc_fqdn: str
    dc_ip: str
    gpo_guid: str
    domain_dn: str

    kerberos: bool
    username: Optional[str]
    password: Optional[str]
    nthash: Optional[str]
    ldaps: bool

    ldap_machine: str
    ldap_nt: Optional[str]
    ldap_aes: Optional[str]
    ldap_iface: str

    smb_mode: str
    smb_ip: str
    smb_share: str
    smb_machine: Optional[str]
    smb_nt: Optional[str]
    smb_aes: Optional[str]
    smb_iface: str

    modules: Optional[List[str]]
    command: Optional[str]
    command_type: str
    command_shell: str

    spoofed_ldap_dn: str
    spoofed_ldap_spn: str
    spoofed_gpo_dn: str
    domain_sid: Optional[str] = None


def parse_config(config_path: str, clean: bool = False) -> Config:
    options = configparser.ConfigParser()
    options.read(config_path)

    ### Argument coherence check
    if not options.has_section("GENERAL"):
        logger.error("Missing GENERAL section in configuration")
        raise typer.Exit(1)

    ou_dn = options.get("GENERAL", "ou-dn", fallback=None)
    domain = options.get("GENERAL", "domain", fallback=None)
    dc_fqdn = options.get("GENERAL", "dc-fqdn", fallback=None)
    dc_ip = options.get("GENERAL", "dc-ip", fallback=dc_fqdn)
    gpo_guid = str(uuid.uuid4()).upper()

    for item_name, val in zip(["ou-dn", "domain", "dc-fqdn"], [ou_dn, domain, dc_fqdn]):
        if not val:
            logger.error(f"Missing '{item_name}' in GENERAL section")
            raise typer.Exit(1)

    domain_dn = ",".join([f"DC={part}" for part in domain.split(".")])

    kerberos = options.getboolean("GENERAL", "kerberos", fallback=False)
    username = options.get("GENERAL", "username", fallback=None)
    password = options.get("GENERAL", "password", fallback=None)
    nthash = options.get("GENERAL", "hash", fallback=None)
    ldaps = options.getboolean("GENERAL", "ldaps", fallback=False)
    
    if not kerberos:
        if not (username and (password or nthash)):
            logger.error("Either username and password, or username and hash must be provided in GENERAL section (unless kerberos is true)")
            raise typer.Exit(1)
        if password is None and nthash is not None:
            password = '0' * 32 + ':' + nthash
    
    if clean is True:
        return Config(
            ou_dn=ou_dn,
            domain=domain,
            dc_fqdn=dc_fqdn,
            dc_ip=dc_ip,
            gpo_guid=gpo_guid,
            domain_dn=domain_dn,
            kerberos=kerberos,
            username=username,
            password=password,
            nthash=nthash,
            ldaps=ldaps,
            ldap_machine="",
            ldap_nt="",
            ldap_aes="",
            ldap_iface="",
            smb_mode="",
            smb_ip="",
            smb_share="",
            smb_machine="",
            smb_nt="",
            smb_aes="",
            smb_iface="",
            modules=[],
            command="",
            command_type="",
            command_shell="",
            spoofed_ldap_dn="",
            spoofed_ldap_spn="",
            spoofed_gpo_dn=""
        )

    if not options.has_section("LDAP"):
        logger.error("Missing LDAP section in configuration")
        raise typer.Exit(1)

    ldap_machine = options.get("LDAP", "ldap-machine", fallback=None)
    if not ldap_machine:
        logger.error("Missing 'ldap-machine' in LDAP section")
        raise typer.Exit(1)
    if not ldap_machine.endswith("$"):
        if typer.confirm(f"'{ldap_machine}' does not end with '$'. Do you still want to continue?"):
            pass
        else:
            raise typer.Exit(1)

    ldap_nt = options.get("LDAP", "ldap-nt", fallback=None)
    ldap_aes = options.get("LDAP", "ldap-aes", fallback=None)
    if not (ldap_nt or ldap_aes):
        logger.error("Either 'ldap-nt' or 'ldap-aes' must be provided in LDAP section")
        raise typer.Exit(1)
    ldap_iface = options.get("LDAP", "ldap-iface", fallback="eth0")

    if not options.has_section("SMB"):
        logger.error("Missing SMB section in configuration")
        raise typer.Exit(1)

    smb_mode = options.get("SMB", "smb-mode", fallback=None)
    smb_ip = options.get("SMB", "smb-ip", fallback=None)
    for item_name, val in zip(["smb-mode", "smb-ip"], [smb_mode, smb_ip]):
        if not val:
            logger.error(f"Missing '{item_name}' in SMB section")
            raise typer.Exit(1)

    smb_mode = smb_mode.lower()
    if smb_mode not in ["domain", "embedded"]:
        logger.error("Invalid 'smb-mode' in SMB section: must be either 'domain' or 'embedded'")
        raise typer.Exit(1)

    smb_share = options.get("SMB", "smb-share", fallback=None)
    smb_machine = options.get("SMB", "smb-machine", fallback=None)
    smb_nt = options.get("SMB", "smb-nt", fallback=None)
    smb_aes = options.get("SMB", "smb-aes", fallback=None)
    smb_iface = options.get("SMB", "smb-iface", fallback="eth0")

    if smb_mode == "domain":
        if not smb_ip or not smb_share:
            logger.error("If 'smb-mode' is 'domain', 'smb-ip' and 'smb-share' must be provided in SMB section")
            raise typer.Exit(1)
    else:
        if not smb_machine:
            smb_machine = ldap_machine
            smb_nt = ldap_nt
            smb_aes = ldap_aes 
        if not smb_share:
            smb_share = "OUned"

    if not options.has_section("COMMANDS"):
        logger.error("Missing COMMANDS section in configuration")
        raise typer.Exit(1)

    modules = options.get("COMMANDS", "modules", fallback=None)
    if modules:
        modules = modules.split(',')
    command = options.get("COMMANDS", "command", fallback=None)
    command_type = options.get("COMMANDS", "command-type", fallback="computer").lower()
    if command_type not in ["computer", "user"]:
        logger.error("Invalid 'command-type' in COMMANDS section: must be either 'computer' or 'user'")
        raise typer.Exit(1)

    command_shell = options.get("COMMANDS", "command-shell", fallback="cmd").lower()
    if command_shell not in ["cmd", "powershell"]:
        logger.error("Invalid 'command-shell' in COMMANDS section: must be either 'cmd' or 'powershell'")
        raise typer.Exit(1)

    if modules and command:
        logger.error("COMMANDS section: 'modules' cannot be specified together with 'command'")
        raise typer.Exit(1)
    if not modules and not command:
        logger.error("COMMANDS section: must specify either 'modules' or 'command'")
        raise typer.Exit(1)

    spoofed_ldap_dn = f"DC={ldap_machine[:-1]},{domain_dn}"
    spoofed_ldap_spn = f"ldap/{ldap_machine[:-1]}.{domain}".lower()
    spoofed_gpo_dn = f"cn={{{gpo_guid}}},cn=policies,cn=system,{spoofed_ldap_dn}"

    return Config(
        ou_dn=ou_dn,
        domain=domain,
        dc_fqdn=dc_fqdn,
        dc_ip=dc_ip,
        gpo_guid=gpo_guid,
        domain_dn=domain_dn,
        kerberos=kerberos,
        username=username,
        password=password,
        nthash=nthash,
        ldaps=ldaps,
        ldap_machine=ldap_machine,
        ldap_nt=ldap_nt,
        ldap_aes=ldap_aes,
        ldap_iface=ldap_iface,
        smb_mode=smb_mode,
        smb_ip=smb_ip,
        smb_share=smb_share,
        smb_machine=smb_machine,
        smb_nt=smb_nt,
        smb_aes=smb_aes,
        smb_iface=smb_iface,
        modules=modules,
        command=command,
        command_type=command_type,
        command_shell=command_shell,
        spoofed_ldap_dn=spoofed_ldap_dn,
        spoofed_ldap_spn=spoofed_ldap_spn,
        spoofed_gpo_dn=spoofed_gpo_dn
    )
