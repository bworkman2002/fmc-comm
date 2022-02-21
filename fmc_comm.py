import requests
import urllib3


class FmcComm:

    def __init__(self, api_path, username, password):

        self.api_path = f'https://{api_path}'
        self._basic_auth = (username, password)
        self._get_headers = None
        self._post_headers = None
        self._domain_uuid = None

        urllib3.disable_warnings()

    @property
    def token(self):
        if not self._get_headers:
            return False
        return True

    def do_login(self):

        auth_resp = requests.post(
            f"{self.api_path}/fmc_platform/v1/auth/generatetoken",
            auth=self._basic_auth,
            verify=False,
        )

        try:
            auth_resp.raise_for_status()
        except requests.HTTPError as e:
            print(str(e))
            return False

        self._get_headers = {"Accept": "application/json",
                             "X-auth-access-token": auth_resp.headers["X-auth-access-token"]}
        self._post_headers = {"Accept": "application/json", "Content-Type": "application/json",
                              "X-auth-access-token": auth_resp.headers["X-auth-access-token"]}
        self._domain_uuid = auth_resp.headers["DOMAIN_UUID"]
        return True

    def get_access_policies(self):

        policy_params = {"limit": 100, "expanded": False}

        get_policy_response = requests.get(
            f"{self.api_path}/fmc_config/v1/domain/{self._domain_uuid}/policy/accesspolicies",
            headers=self._get_headers,
            params=policy_params,
            verify=False,
        )

        try:
            get_policy_response.raise_for_status()
        except requests.HTTPError as e:
            print(str(e))
            return None

        return get_policy_response.json()["items"]

    def add_access_policy(self, policy):

        add_policy_response = requests.post(
            f"{self.api_path}/fmc_config/v1/domain/{self._domain_uuid}/policy/accesspolicies",
            headers=self._get_headers, json=policy, verify=False)

        try:
            add_policy_response.raise_for_status()
        except requests.HTTPError as e:
            print(str(e))
            return False

        if add_policy_response.ok:
            return True

    def delete_access_policy(self, policy_id):

        policy = {
            "ignoreWarning": "true"
        }

        delete_resp = requests.delete(f"{self.api_path}/fmc_config/v1/domain"
                                      f"/{self._domain_uuid}/policy/accesspolicies/{policy_id}",
                                      params=policy, headers=self._post_headers, verify=False)

        try:
            delete_resp.raise_for_status()
        except requests.HTTPError as e:
            print(str(e))
            return False

        if delete_resp.ok:
            return True

    def get_prefilter(self):

        pr_resp = requests.get(f"{self.api_path}/fmc_config/v1/domain/{self._domain_uuid}/policy/prefilterpolicies",
                               headers=self._get_headers, verify=False)
        try:
            pr_resp.raise_for_status()
        except requests.HTTPError as e:
            print(str(e))
            return None

        return pr_resp.json()['items']


def main():

    # Instantiate the communicator
    fmc = FmcComm(api_path='fmcrestapisandbox.cisco.com/api', username='bworkman20', password='YBegvQYe')

    # If the Communicator doesn't have token, login and get one
    if not fmc.token:
        fmc.do_login()

    # Retrieve a current list of access policies
    policies = fmc.get_access_policies()
    if policies:
        policy_names = {}
        for policy in policies:
            policy_names[policy['name']] = policy['id']
            print(f"ID: {policy['id']}  Name: {policy['name']}")

        # Define a new policy to add with a minimum of information.
        new_policy = {
            "type": "AccessPolicy",
            "name": "Bworkman_Test_Policy",
            "defaultAction": {"action": "BLOCK"},
        }

        # See if the new policy already exists
        if not policy_names.get(new_policy['name'], False):
            if fmc.add_access_policy(policy=new_policy):
                print('Successfully added new policy.')
        else:
            if fmc.delete_access_policy(policy_names.get(new_policy['name'], '')):
                print(f"Access policy {new_policy['name']} has been deleted.")

    pf = fmc.get_prefilter()
    print(pf)


if __name__ == '__main__':
    main()
