"""AWS API action -> MITRE ATT&CK for Cloud (IaaS matrix) mapping.

The table below is the detection content of this project: it is what turns a raw
``eventName`` into something an analyst can reason about. Actions we have not
explicitly enumerated still get classified by :func:`classify` using verb and
service heuristics, so an unseen API call degrades to a sensible guess instead
of "Unknown".
"""

from __future__ import annotations

from dataclasses import dataclass

# Severity ladder used across the whole engine.
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Rough order in which an intrusion progresses. Used to sort the attack chain
# and to decide whether an actor has "advanced" between phases.
TACTIC_ORDER = [
    "Initial Access",
    "Discovery",
    "Credential Access",
    "Privilege Escalation",
    "Persistence",
    "Defense Evasion",
    "Lateral Movement",
    "Collection",
    "Exfiltration",
    "Impact",
]


@dataclass(frozen=True)
class Technique:
    tactic: str
    technique_id: str
    technique_name: str
    severity: str

    @property
    def label(self) -> str:
        return f"{self.technique_id} - {self.technique_name}"

    def to_dict(self) -> dict:
        return {
            "tactic": self.tactic,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "severity": self.severity,
        }


def _t(tactic: str, tid: str, name: str, severity: str) -> Technique:
    return Technique(tactic, tid, name, severity)


# --------------------------------------------------------------------------- #
# Explicit action mapping
# --------------------------------------------------------------------------- #
DISCOVERY_ACCOUNT = _t("Discovery", "T1087.004", "Account Discovery: Cloud Account", "MEDIUM")
DISCOVERY_SERVICE = _t("Discovery", "T1526", "Cloud Service Discovery", "MEDIUM")
DISCOVERY_INFRA = _t("Discovery", "T1580", "Cloud Infrastructure Discovery", "MEDIUM")
DISCOVERY_PERMS = _t("Discovery", "T1069.003", "Permission Groups Discovery: Cloud Groups", "HIGH")
CRED_ACCESS_SECRETS = _t("Credential Access", "T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "CRITICAL")
CRED_ACCESS_STORE = _t("Credential Access", "T1555.006", "Credentials from Password Stores: Cloud Secrets Management Stores", "CRITICAL")
PRIVESC_ROLE = _t("Privilege Escalation", "T1548.005", "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access", "CRITICAL")
PERSISTENCE_ACCOUNT = _t("Persistence", "T1098.001", "Account Manipulation: Additional Cloud Credentials", "CRITICAL")
PERSISTENCE_ROLES = _t("Persistence", "T1098.003", "Account Manipulation: Additional Cloud Roles", "CRITICAL")
PERSISTENCE_CREATE = _t("Persistence", "T1136.003", "Create Account: Cloud Account", "CRITICAL")
COLLECTION_STORAGE = _t("Collection", "T1530", "Data from Cloud Storage", "HIGH")
EXFIL_STORAGE = _t("Exfiltration", "T1537", "Transfer Data to Cloud Account", "CRITICAL")
EVASION_LOGS = _t("Defense Evasion", "T1562.008", "Impair Defenses: Disable or Modify Cloud Logs", "CRITICAL")
EVASION_TRAIL = _t("Defense Evasion", "T1578", "Modify Cloud Compute Infrastructure", "HIGH")
LATERAL_EXEC = _t("Lateral Movement", "T1021.007", "Remote Services: Cloud Services", "HIGH")
IMPACT_DESTROY = _t("Impact", "T1485", "Data Destruction", "CRITICAL")
IMPACT_RANSOM = _t("Impact", "T1486", "Data Encrypted for Impact", "CRITICAL")

ACTION_MAP: dict[str, Technique] = {
    # -- Discovery / recon --------------------------------------------------
    "GetCallerIdentity": DISCOVERY_ACCOUNT,
    "ListUsers": DISCOVERY_ACCOUNT,
    "ListRoles": DISCOVERY_ACCOUNT,
    "ListAccountAliases": DISCOVERY_ACCOUNT,
    "GetAccountSummary": DISCOVERY_ACCOUNT,
    "ListAccessKeys": DISCOVERY_ACCOUNT,
    "ListBuckets": DISCOVERY_SERVICE,
    "ListSecrets": DISCOVERY_SERVICE,
    "ListFunctions": DISCOVERY_SERVICE,
    "ListTables": DISCOVERY_SERVICE,
    "ListKeys": DISCOVERY_SERVICE,
    "ListTopics": DISCOVERY_SERVICE,
    "ListQueues": DISCOVERY_SERVICE,
    "DescribeInstances": DISCOVERY_INFRA,
    "DescribeSecurityGroups": DISCOVERY_INFRA,
    "DescribeDBInstances": DISCOVERY_INFRA,
    "DescribeSnapshots": DISCOVERY_INFRA,
    "DescribeVpcs": DISCOVERY_INFRA,
    "GetBucketAcl": DISCOVERY_INFRA,
    "GetBucketPolicy": DISCOVERY_INFRA,
    "ListAttachedUserPolicies": DISCOVERY_PERMS,
    "ListAttachedRolePolicies": DISCOVERY_PERMS,
    "ListUserPolicies": DISCOVERY_PERMS,
    "ListRolePolicies": DISCOVERY_PERMS,
    "ListGroupsForUser": DISCOVERY_PERMS,
    "GetPolicyVersion": DISCOVERY_PERMS,
    "SimulatePrincipalPolicy": DISCOVERY_PERMS,
    # -- Credential access --------------------------------------------------
    "GetSecretValue": CRED_ACCESS_STORE,
    "BatchGetSecretValue": CRED_ACCESS_STORE,
    "GetParameter": CRED_ACCESS_STORE,
    "GetParameters": CRED_ACCESS_STORE,
    "GetParametersByPath": CRED_ACCESS_STORE,
    "Decrypt": CRED_ACCESS_STORE,
    "GetSessionToken": CRED_ACCESS_SECRETS,
    "GetFederationToken": CRED_ACCESS_SECRETS,
    "GetAuthorizationToken": CRED_ACCESS_SECRETS,
    # -- Privilege escalation ----------------------------------------------
    "AssumeRole": PRIVESC_ROLE,
    "AssumeRoleWithWebIdentity": PRIVESC_ROLE,
    "AssumeRoleWithSAML": PRIVESC_ROLE,
    "PutUserPolicy": PRIVESC_ROLE,
    "PutRolePolicy": PRIVESC_ROLE,
    "AttachUserPolicy": PRIVESC_ROLE,
    "AttachRolePolicy": PRIVESC_ROLE,
    "AttachGroupPolicy": PRIVESC_ROLE,
    "UpdateAssumeRolePolicy": PRIVESC_ROLE,
    "CreatePolicyVersion": PRIVESC_ROLE,
    "SetDefaultPolicyVersion": PRIVESC_ROLE,
    "PassRole": PRIVESC_ROLE,
    # -- Persistence --------------------------------------------------------
    "CreateAccessKey": PERSISTENCE_ACCOUNT,
    "UpdateAccessKey": PERSISTENCE_ACCOUNT,
    "CreateLoginProfile": PERSISTENCE_ACCOUNT,
    "UpdateLoginProfile": PERSISTENCE_ACCOUNT,
    "CreateServiceSpecificCredential": PERSISTENCE_ACCOUNT,
    "CreateUser": PERSISTENCE_CREATE,
    "CreateRole": PERSISTENCE_ROLES,
    "AddUserToGroup": PERSISTENCE_ROLES,
    "CreateVirtualMFADevice": PERSISTENCE_ACCOUNT,
    "DeactivateMFADevice": PERSISTENCE_ACCOUNT,
    # -- Defense evasion ----------------------------------------------------
    "StopLogging": EVASION_LOGS,
    "DeleteTrail": EVASION_LOGS,
    "UpdateTrail": EVASION_LOGS,
    "PutEventSelectors": EVASION_LOGS,
    "DeleteFlowLogs": EVASION_LOGS,
    "DeleteLogGroup": EVASION_LOGS,
    "DeleteLogStream": EVASION_LOGS,
    "DeleteDetector": EVASION_LOGS,
    "UpdateDetector": EVASION_LOGS,
    "DisassociateFromMasterAccount": EVASION_LOGS,
    "AuthorizeSecurityGroupIngress": EVASION_TRAIL,
    "ModifyInstanceAttribute": EVASION_TRAIL,
    # -- Lateral movement ---------------------------------------------------
    "SendCommand": LATERAL_EXEC,
    "StartSession": LATERAL_EXEC,
    "Invoke": LATERAL_EXEC,
    "RunInstances": LATERAL_EXEC,
    "CreateFunction": LATERAL_EXEC,
    "UpdateFunctionCode": LATERAL_EXEC,
    "ExecuteCommand": LATERAL_EXEC,
    # -- Collection / exfiltration -----------------------------------------
    "GetObject": COLLECTION_STORAGE,
    "ListObjects": COLLECTION_STORAGE,
    "ListObjectsV2": COLLECTION_STORAGE,
    "SelectObjectContent": COLLECTION_STORAGE,
    "GetItem": COLLECTION_STORAGE,
    "Scan": COLLECTION_STORAGE,
    "Query": COLLECTION_STORAGE,
    "CreateDBSnapshot": COLLECTION_STORAGE,
    "CopyObject": EXFIL_STORAGE,
    "PutBucketPolicy": EXFIL_STORAGE,
    "PutBucketAcl": EXFIL_STORAGE,
    "ModifySnapshotAttribute": EXFIL_STORAGE,
    "ModifyDBSnapshotAttribute": EXFIL_STORAGE,
    "ShareSnapshot": EXFIL_STORAGE,
    # -- Impact -------------------------------------------------------------
    "DeleteObject": IMPACT_DESTROY,
    "DeleteBucket": IMPACT_DESTROY,
    "DeleteDBInstance": IMPACT_DESTROY,
    "TerminateInstances": IMPACT_DESTROY,
    "ScheduleKeyDeletion": IMPACT_RANSOM,
    "DisableKey": IMPACT_RANSOM,
    "PutBucketEncryption": IMPACT_RANSOM,
}

UNCLASSIFIED = _t("Unclassified", "T0000", "Unmapped API Action", "LOW")

# Verb-level fallbacks, checked in order, for actions not in ACTION_MAP.
_VERB_FALLBACKS: list[tuple[tuple[str, ...], Technique]] = [
    (("List", "Describe", "Get", "Lookup", "Search", "Head"), DISCOVERY_SERVICE),
    (("Assume", "Attach", "Promote", "Elevate"), PRIVESC_ROLE),
    (("Create", "Add", "Register", "Import"), PERSISTENCE_ROLES),
    (("Put", "Update", "Modify", "Set", "Enable"), EVASION_TRAIL),
    (("Delete", "Remove", "Terminate", "Stop", "Disable", "Revoke"), IMPACT_DESTROY),
    (("Send", "Invoke", "Run", "Execute", "Start"), LATERAL_EXEC),
]


def classify(event_name: str, event_source: str = "") -> Technique:
    """Map an AWS API action to an ATT&CK technique.

    Exact matches win; otherwise the action's verb decides. ``event_source`` is
    used to sharpen a couple of ambiguous verbs (e.g. ``Query``/``Scan`` are
    data reads on DynamoDB but discovery elsewhere).
    """
    if not event_name:
        return UNCLASSIFIED

    if event_name in ACTION_MAP:
        technique = ACTION_MAP[event_name]
        if event_name in {"Query", "Scan"} and "dynamodb" not in event_source.lower():
            return DISCOVERY_SERVICE
        return technique

    for prefixes, technique in _VERB_FALLBACKS:
        if event_name.startswith(prefixes):
            return technique

    return UNCLASSIFIED


def severity_rank(severity: str) -> int:
    """Numeric rank so severities can be compared and max()'d."""
    try:
        return SEVERITY_ORDER.index(severity.upper())
    except (ValueError, AttributeError):
        return 0


def highest_severity(severities: list[str]) -> str:
    if not severities:
        return "INFO"
    return max(severities, key=severity_rank)


def tactic_rank(tactic: str) -> int:
    """Position in the kill chain; unknown tactics sort last."""
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(TACTIC_ORDER)
