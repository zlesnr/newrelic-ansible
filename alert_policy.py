#! /usr/bin/env python

import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import requests
import json


def main():
    module = AnsibleModule(
        argument_spec=dict(
            api_key=dict(required=True, no_log=True),
            account_id=dict(required=True, no_log=False),
            incident_preference=dict(required=True, no_log=False),
            name=dict(required=True, no_log=False),
        )
    )

    try:
        policy = get_policy(module)
        if policy:
            update_policy(policy, module)
        else:
            create_policy(module)

        module.exit_json(changed=False, msg=policy)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())


def create_policy(module):
    mutation = policy_create_mutation(module)
    response = nerdgraph_query(mutation, module)
    if response.status_code != 200:
        module.fail_json(msg="create failed: {0}".format(response.text))

    json_data = json.loads(response.text)
    module.exit_json(changed=True, msg=json_data)


def update_policy(policy, module):
    mutation = policy_update_mutation(policy, module)
    response = nerdgraph_query(mutation, module)
    if response.status_code != 200:
        module.fail_json(msg="update failed: {0}".format(response.text))

    json_data = json.loads(response.text)
    if policy.get("incidentPreference") != module.params.get("incident_preference"):
        module.exit_json(changed=True, msg=json_data)


def get_policy(module):
    query = policy_search_query(module)
    response = nerdgraph_query(query, module)
    if response.status_code != 200:
        module.fail_json(msg="query failed: {0}".format(response.text))

    data = json.loads(response.text)

    name = module.params.get('name', None)

    for policy in data['data']['actor']['account']['alerts']['policiesSearch']['policies']:
        if policy["name"] == name:
            return policy

    return None


def nerdgraph_query(query, module):
    headers = {
        "Content-Type": "application/json",
        "API-Key": module.params.get("api_key", None),
    }

    url = 'https://api.newrelic.com/graphql'
    r = requests.post(url, json={'query': query}, headers=headers)
    return r


def policy_create_mutation(module):
    return '''mutation {
        alertsPolicyCreate(accountId: %s, policy: {
            incidentPreference: %s, name: "%s"}) {
                accountId
                id
                incidentPreference
                name
            }
        }
        ''' % (
        module.params.get("account_id"),
        module.params.get("incident_preference"),
        module.params.get("name"),
    )


def policy_update_mutation(policy, module):
    return '''mutation {
        alertsPolicyUpdate(policy: {incidentPreference: %s, name: "%s"}, accountId: %s, id: %s) {
            accountId
            id
            incidentPreference
            name
        }
        }''' % (
        module.params.get("incident_preference"),
        module.params.get("name"),
        module.params.get("account_id"),
        policy.get("id"),
    )


def policy_search_query(module):
    return '''{
            actor {
                account(id: %s) {
                    alerts {
                        policiesSearch {
                            nextCursor
                            policies {
                                accountId
                                id
                                incidentPreference
                                name
                            }
                        }
                    }
                }
            }
        }''' % module.params.get("account_id", None)


if __name__ == '__main__':
    main()
