import logging

from ldap3 import Server, Connection, SUBTREE, MODIFY_REPLACE, MODIFY_DELETE, ALL, NTLM

def ldap_check_credentials(ldap_ip, username, password, domain):
    try:
        server = Server(f'ldap://{ldap_ip}:389', get_info=ALL)
        conn = Connection(server, user=f"{domain}\\{username}", password=password, authentication=NTLM, auto_bind=True)
        conn.unbind()
        return True
    except:
        import traceback
        traceback.print_exc()
        return False

def get_attribute(ldap_session, dn, attribute):
    try:
        ldap_session.search(
        search_base=dn,
        search_filter='(objectClass=*)',
        search_scope=SUBTREE,
        attributes=[attribute,],
        )

        searchResult = ldap_session.response[0]
        value = searchResult['attributes'][attribute]
        return value
    except:
        logging.error(f"‼️  Error: couldn't find attribute {attribute} for dn {dn}. Things will probably break.")
        return None
    

def modify_attribute(ldap_session, dn, attribute, new_value):
    result = ldap_session.modify(dn, {attribute: [(MODIFY_REPLACE, [new_value])]})
    return result

def unset_attribute(ldap_session, dn, attribute):
    result = ldap_session.modify(dn, {attribute: [(MODIFY_DELETE, [])]})
    return result
