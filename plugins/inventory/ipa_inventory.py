# -*- coding: utf-8 -*-

# Copyright (c) Darcy Morrissette
# Credit to the Ansible Project for the original inventory script
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = '''
    name: darcystan.ipa_inv.ipa_inventory
    plugin_type: inventory
    author:
      - Darcy Morrissette <darcy.morrissette@stantec.com>

    short_description: FreeIPA/RHIdM inventory source

    description:
      - Fetches hosts through the API and groups them by host_groups
      - Uses ipa_inventory.(yml|yaml) YAML configuration file to set parameter values.

    extends_documentation_fragment:
      - inventory_cache

    options:
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
    requirements:
    - "python >= 3.6"
    - "PyYAML >= 3.11"
'''

EXAMPLES = '''
# File must be named (ipa|idm)_inventory.(yaml|yml) or (ipa|idm)_inv.(yaml|yml)

# Authenticate with token, and return all pods and services for all namespaces
plugin: darcystan.ipa_inv.ipa_inventory
ipa_server: example-server.mydomain.com
ipa_user: api_user
ipa_pass: mysecurepass
validate_certs: false
'''

import json
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves import http_cookiejar as cookiejar
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable, Cacheable

class InventoryModule(BaseInventoryPlugin, Constructable, Cacheable):

    NAME = 'darcystan.ipa_inv.ipa_inventory'

    def verify_file(self, path):
        valid = False
        if super(InventoryModule, self).verify_file(path):
            if path.endswith(
                (
                    "ipa_inventory.yaml",
                    "ipa_inventory.yml",
                    "idm_inventory.yaml",
                    "idm_inventory.yml",
                    "ipa_inv.yaml",
                    "ipa_inv.yml",
                    "idm_inv.yaml",
                    "idm_inv.yml",
                )
            ):
                valid = True
            else:
                self.display.vvv(
                    "Skipping due to inventory source file name mismatch. "
                    "The file name has to end with one of the following: "
                    "ipa_inventory.yaml, ipa_inventory.yml, "
                    "idm_inventory.yaml, idm_inventory.yml, "
                    "ipa_inv.yaml, ipa_inv.yml, "
                    "idm_inv.yaml, idm_inv.yml."
                )
        return valid

    # Put a cookie in the cookie-jar
    def get_cookie(self, base_url, ipauser, ipapassword, validate_certs):
        login_req = ""
        login_url = "{}/session/login_password".format(base_url)
        headers = {
            "referer": base_url,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "text/plain"
        }
        data = "user={0}&password={1}".format(ipauser, ipapassword)
        cookies = cookiejar.LWPCookieJar()
        try:
            login_req = open_url(login_url, method='POST', headers=headers, data=data, cookies=cookies, validate_certs=validate_certs)
            if login_req.code == 200:
                cookie_list = []
                for ck in cookies:
                    cookie_list.append(str(ck.name) + "=" + str(ck.value))
            else:
                AnsibleModule.fail_json(changed=False, msg="Login Failed!", reason=login_req.read(),
                response="HTTP status_code: " + str(login_req.code))
        except Exception as e:
            raise AnsibleParserError("API Call failed! Exception during login: " + str(e))
        return cookies

    def get_inventory(self):
        '''
        This function prints a list of all host groups. This function requires
        one argument, the FreeIPA/IPA API object.
        '''
        validate_certs = True

        ipaserver = self.get_option("ipa_server")
        try:
            ipaserver
        except NameError:
            raise AnsibleError('ERROR: The ipa_server option in the inventory config is not set (Ex: idm_inv.yml). ')

        ipauser = self.get_option("ipa_user")
        try:
            ipauser
        except NameError:
            raise AnsibleError('ERROR: The ipa_user option in the inventory config is not set (Ex: idm_inv.yml). ')

        ipapassword = self.get_option("ipa_pass")
        try:
            ipapassword
        except NameError:
            raise AnsibleError('ERROR: The ipa_pass option in the inventory config is not set (Ex: idm_inv.yml). ')

        hostgroup = self.get_option("ipa_hostgroup")
        try:
            hostgroup
        except NameError:
            raise AnsibleError('ERROR: The ipa_hostgroup option in the inventory config is not set (Ex: idm_inv.yml). ')

        ipaversion = self.get_option("ipa_version")
        if ipaversion is None:
            ipaversion = "2.237"
        try:
            ipaversion
        except NameError:
            raise AnsibleError('ERROR: The ipa_version option in the inventory config is not set (Ex: idm_inv.yml). ')

        validate_certs = self.get_option("validate_certs")
        try:
            validate_certs
        except NameError:
            raise AnsibleError('ERROR: The validate_certs option in the inventory config is not set (Ex: idm_inv.yml). ')

        base_url = "https://{}/ipa".format(ipaserver)
        cookies = self.get_cookie(base_url, ipauser, ipapassword, validate_certs)
        # Don't include any servers in the following hostgroups in inventory list
        ignore_hostgroups = ['archive']
        ignore_members = []
        result = {}

        url_login = "{0}/session/json".format(base_url)
        headers = {
            "referer": base_url,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        data = json.dumps({
            "method": "hostgroup_find",
            "params": [
                [""],
                {
                    "all": "true",
                    "version": ipaversion
                }
            ],
            "id": 0
        })
        try:
            request = open_url(url_login, method='POST', headers=headers, data=data, cookies=cookies, validate_certs=validate_certs)
            raw_result = json.loads(request.read().decode('utf8'))
        except Exception as e:
            AnsibleModule.fail_json(changed=False, msg="API Call failed! Exception during api call", reason=str(e))
        result = raw_result['result']['result']

        # Get a list of all hosts to be excluded
        for hostgroup in result:
            if any(x in hostgroup['cn'] for x in ignore_hostgroups):
                if 'member_host' in hostgroup:
                    ignore_members += [host for host in hostgroup['member_host']]

        for hostgroup in result:
            # Get direct and indirect members (nested hostgroups) of hostgroup
            members = []
            if 'member_host' in hostgroup:
                members = [host for host in hostgroup['member_host']]
            if 'memberindirect_host' in hostgroup:
                members += (host for host in hostgroup['memberindirect_host'])

            self.inventory.add_group(hostgroup['cn'][0])
            members = set(members) - set(ignore_members)
            for member in members:
                self.inventory.add_host(host=member, group=hostgroup['cn'][0])

    def parse(self, inventory, loader, path, cache=True):
        super(InventoryModule, self).parse(inventory, loader, path)

        self.load_cache_plugin()
        self._read_config_data(path)

        # cache settings
        cache_key = self.get_cache_key(path)
        use_cache = self.get_option("cache") and cache
        update_cache = self.get_option("cache") and not cache

        records = None
        if use_cache:
            try:
                records = self._cache[cache_key]
            except KeyError:
                update_cache = True

        if records is None:
            records = self.get_inventory()

        if update_cache:
            self._cache[cache_key] = records
