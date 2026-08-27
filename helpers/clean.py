import os
import json
from datetime import datetime
from ldap3 import MODIFY_DELETE
from helpers.utils import logger, bcolors

def clean_create_folder():
    clean_folder = datetime.now().strftime("%Y_%m_%d_%H%M%S_%f")
    os.makedirs("cleaning", exist_ok=True)
    os.makedirs(os.path.join("cleaning", clean_folder))
    os.makedirs(os.path.join("cleaning", clean_folder, "revert"))

    with open(os.path.join("cleaning", clean_folder, "actions.json"), "w") as f:
        json.dump({"actions": []}, f)
    return os.path.join("cleaning", clean_folder)

def clean_save_action(clean_folder, action, item, attribute=None, old_value=None, new_value=None, added=None):
    with open(os.path.join(clean_folder, "actions.json"), 'r+') as f:
        data = json.load(f)
        data["actions"].append({
            "action": action,
            "item": item,
            "attribute": attribute,
            "old_value": old_value,
            "new_value": new_value,
            "added": added
        })
        f.seek(0)
        json.dump(data, f, indent=2, default=str)

def revert_ou_gplink(ldap_session, clean_folder):
    # Read actions.json and revert gPLink
    actions_file = os.path.join(clean_folder, "actions.json")
    if os.path.exists(actions_file):
        try:
            with open(actions_file, "r") as f:
                data = json.load(f)
            
            for action in data.get("actions", []):
                if action.get("action") == "ldap_modify_attribute" and action.get("attribute") == "gPLink":
                    item_dn = action.get("item")
                    added_gplink = action.get("added")
                    logger.warning(f"[*] Removing following gPLink item: '{added_gplink}' from '{item_dn}'")
                    from helpers.ldap import get_entries, modify_attribute
                    try:
                        from helpers.ldap import get_entries
                        ou_entries = get_entries(
                            ldap_session=ldap_session,
                            search_base=item_dn,
                            search_filter="(objectClass=*)",
                            search_scope=0,
                            attributes=["gPLink"]
                        )
                        current_gplink = ou_entries[0].get("attributes", {}).get("gPLink")
                        logger.warning(f"[*] Current gPLink: '{current_gplink}'")
                        if isinstance(current_gplink, list):
                            current_gplink = current_gplink[0] if current_gplink else ""
                        elif current_gplink is None:
                            current_gplink = ""
                        else:
                            current_gplink = str(current_gplink)

                        if added_gplink and added_gplink in current_gplink:
                            new_gplink = current_gplink.replace(added_gplink, "")
                            if not new_gplink:
                                ldap_session.modify(item_dn, {"gPLink": [(MODIFY_DELETE, [])]})
                            else:
                                modify_attribute(ldap_session, item_dn, "gPLink", new_gplink)
                            logger.warning(f"[*] Updated gPLink: '{new_gplink}'")
                            logger.warning(f"{bcolors.OKGREEN}[+] Reverted added gPLink for '{item_dn}'{bcolors.ENDC}")
                        else:
                            logger.warning(f"{bcolors.WARNING}[!] Added gPLink not found in '{item_dn}' (maybe already removed?), nothing to revert{bcolors.ENDC}")
                    except Exception as e:
                        logger.error(f"Failed to revert gPLink for '{item_dn}': {e}")
        except Exception as e:
            logger.error(f"Failed to read {actions_file} or revert actions: {e}")
