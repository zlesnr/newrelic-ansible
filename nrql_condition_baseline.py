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
            description=dict(required=False, no_log=False),
            enabled=dict(required=False, no_log=False),
            # expiration=dict(required=False, no_log=False),
            name=dict(required=True, no_log=False),
            nrql_query=dict(required=True, no_log=False),
            policy_id=dict(required=True, no_log=False),
            # signal=dict(required=True, no_log=False),
            # terms=dict(required=True, no_log=False),
            # condition_type=dict(required=True, no_log=False),
            baseline_direction=dict(required=True, no_log=False),
            runbook_url=dict(required=False, no_log=False),
            expiration_duration=dict(required=True, no_log=False),
            critical_operator=dict(required=True, no_log=False),
            critical_threshold=dict(required=True, no_log=False),
            critical_threshold_duration=dict(required=True, no_log=False),
            critical_threshold_occurrences=dict(required=True, no_log=False),
            violation_time_limit=dict(required=True, no_log=False),
        )
    )

    try:
        condition = get_condition(module)
        if condition:
            update_condition(condition, module)
        else:
            create_condition(module)

        module.exit_json(changed=False, msg="no update")
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())


def create_condition(module):
    mutation = nrql_condition_baseline_create_mutation(module)
    response = nerdgraph_query(mutation, module)
    if response.status_code != 200:
        module.fail_json(msg="create_condition failed: {0}".format(response.text))

    data = json.loads(response.text)

    errors = data.get("errors", None)
    if errors:
        module.fail_json(msg=errors)

    module.exit_json(changed=True, msg=data)


def update_condition(condition, module):
    mutation = nrql_condition_baseline_update_mutation(condition, module)
    response = nerdgraph_query(mutation, module)
    if response.status_code != 200:
        module.fail_json(msg="update_condition failed: {0}".format(response.text))

    data = json.loads(response.text)
    changed = False

    if data["data"]["alertsNrqlConditionBaselineUpdate"] != condition:
        changed = True

    module.exit_json(
        changed=changed, msg=data["data"]["alertsNrqlConditionBaselineUpdate"]
    )


def nerdgraph_query(query, module):
    headers = {
        "Content-Type": "application/json",
        "API-Key": module.params.get("api_key", None),
    }

    url = "https://api.newrelic.com/graphql"
    r = requests.post(url, json={"query": query}, headers=headers)
    return r


def nrql_condition_fields(module):
    return """
        description
        enabled
            expiration {
            closeViolationsOnExpiration
            expirationDuration
            openViolationOnExpiration
        }
        id
        name
        nrql {
            query
        }
        policyId
        runbookUrl
        signal {
            evaluationOffset
            fillOption
            fillValue
        }
        terms {
            operator
            priority
            threshold
            thresholdDuration
            thresholdOccurrences
        }
        type
        violationTimeLimit
        """


def nrql_condition_baseline_query(module):
    fields = nrql_condition_fields(module)
    account_id = module.params.get("account_id", None)
    return """{
            actor {
                account(id: %s) {
                    alerts {
                        nrqlConditionsSearch {
                            nrqlConditions {
                                %s
                                ... on AlertsNrqlBaselineCondition {
                                baselineDirection
                                %s
                                }
                            }
                            nextCursor
                        }
                    }
                }
            }
        }""" % (
        account_id,
        fields,
        fields,
    )


def condition_string(module):
    name = module.params.get("name", None)
    description = module.params.get("description", None)

    baseline_direction = module.params.get("baseline_direction", None)
    enabled = module.params.get("enabled", "false")
    nrql_query = module.params.get("nrql_query", None)
    runbook_url = module.params.get("runbook_url", None)

    expiration_duration = module.params.get("expiration_duration", None)

    critical_operator = module.params.get("critical_operator", None)
    critical_threshold = module.params.get("critical_threshold", None)
    critical_threshold_duration = module.params.get("critical_threshold_duration", None)
    critical_threshold_occurrences = module.params.get(
        "critical_threshold_occurrences", None
    )
    violation_time_limit = module.params.get("violation_time_limit", None)

    return """
        condition: {
            name: "%s",
            description: "%s",
            baselineDirection: %s,
            enabled: %s,
            expiration: {
                closeViolationsOnExpiration: false,
                expirationDuration: %s,
                openViolationOnExpiration: false
            },
            nrql: {
                query: "%s"
            },
            runbookUrl: "%s",
            terms: {
                operator: %s,
                priority: CRITICAL,
                threshold: %s,
                thresholdDuration: %s,
                thresholdOccurrences: %s
            },
            violationTimeLimit: %s
        }""" % (
        name,
        description,
        baseline_direction,
        enabled,
        expiration_duration,
        nrql_query,
        runbook_url,
        critical_operator,
        critical_threshold,
        critical_threshold_duration,
        critical_threshold_occurrences,
        violation_time_limit,
    )


def nrql_condition_baseline_update_mutation(condition, module):
    fields = nrql_condition_fields(module)
    account_id = module.params.get("account_id", None)
    conditionMutationString = condition_string(module)
    id = condition.get("id", None)

    return """
        mutation {
            alertsNrqlConditionBaselineUpdate(
                accountId: %s,
                %s
                id: "%s"
            ) {
                baselineDirection
                %s
            }
        }""" % (
        account_id,
        conditionMutationString,
        id,
        fields,
    )


def nrql_condition_baseline_create_mutation(module):
    fields = nrql_condition_fields(module)
    account_id = module.params.get("account_id", None)
    conditionMutationString = condition_string(module)
    policy_id = module.params.get("policy_id", None)

    return """mutation {
        alertsNrqlConditionBaselineCreate(
            accountId: %s,
            %s
            policyId: "%s"
            ) {
                baselineDirection
                %s
            }
        }""" % (
        account_id,
        conditionMutationString,
        policy_id,
        fields,
    )


def get_condition(module):
    query = nrql_condition_baseline_query(module)
    response = nerdgraph_query(query, module)

    if response.status_code != 200:
        module.fail_json(msg="query failed: {0}".format(response.text))

    id = module.params.get("id", None)
    name = module.params.get("name", None)

    data = json.loads(response.text)

    module.debug(str(data))

    for condition in data["data"]["actor"]["account"]["alerts"]["nrqlConditionsSearch"][
        "nrqlConditions"
    ]:
        if id is not None and condition["id"] == id:
            return condition

        if name is not None and condition["name"] == name:
            return condition

    return None


if __name__ == "__main__":
    main()
