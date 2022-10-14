### Stantec IPA Inventory Collection

- ipa_inventory: IPA/IdM API Inventory plugin

Created by: Darcy Morrissette

### Install the plugin
```
ansible-galaxy collection install darcystan.ipa_inv
```

### Example usage:
```
plugin: darcystan.ipa_inv.ipa_inventory
ipa_server: server.example.com
ipa_user: example_user
validate_certs: True
cache: False
ipa_pass: MyS3cur3P@$$ # Recommended to store in Vault
```

### Options:
```
plugin:
  description: token that ensures this is a source file for the 'ipa_inventory' plugin.
  required: True
  choices: ['ipa_inventory', 'darcystan.ipa_inv.ipa_inventory']
ipa_server:
  description: FQDN of the RHIdM/FreeIPA Server
  required: true
  type: str
  aliases: [ idm_server ]
  env:
    - name: IPA_SERVER
ipa_user:
  description: User for connecting to the API
  required: true
  type: str
  aliases: [ idm_user ]
  env:
    - name: IPA_USER
ipa_pass:
  description: Password for the API user
  required: true
  type: str
  aliases: [ idm_pass ]
  env:
    - name: IPA_PASS
ipa_hostgroup:
  description: Hostgroup to use as the root of the Ansible inventory
  required: false
  type: str
  aliases: [ idm_hostgroup ]
  env:
    - name: IPA_HOSTGROUP
ipa_version:
  description: IPA API Version to use when retreiving the inventory
  required: false
  default: "2.237"
  type: str
  aliases: [ idm_version ]
  env:
    - name: IPA_VERSION
validate_certs:
  description: Whether or not to verify the API server's SSL certificates.
  required: false
  default: True
  type: bool
  aliases: [ verify_ssl ]
  env:
    - name: VALIDATE_CERTS
```
