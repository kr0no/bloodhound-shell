"""Edge (relationship) taxonomy used by the relationship views."""

from __future__ import annotations

from typing import Literal

MEMBER_OF = "MemberOf"
HAS_SESSION = "HasSession"
# Directory tree (domain -> OU / container -> ... -> object) and GPO links (GPO -> domain / OU).
CONTAINS = "Contains"
GP_LINK = "GPLink"

# Direct object control (ACL abuse).
ACL_EDGES: frozenset[str] = frozenset({
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
    "ForceChangePassword", "AddMember", "AddSelf", "AllExtendedRights",
    "AddKeyCredentialLink", "WriteSPN", "WriteAccountRestrictions",
    "WriteGPLink", "WriteOwnerLimitedRights", "OwnsLimitedRights",
})  # OwnsRaw / WriteOwnerRaw are intentionally excluded: they duplicate Owns / WriteOwner.

# Rights that let the holder re-enable a disabled account (write its userAccountControl, directly
# or by first granting themselves the right). WriteAccountRestrictions covers userAccountControl.
ENABLE_EDGES: frozenset[str] = frozenset({
    "GenericAll", "GenericWrite", "WriteAccountRestrictions", "Owns", "WriteDacl", "WriteOwner",
})

# Credential access primitives.
CREDENTIAL_EDGES: frozenset[str] = frozenset({
    "ReadLAPSPassword", "ReadGMSAPassword", "SyncLAPSPassword", "DumpSMSAPassword",
    "DCSync", "GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "HasSIDHistory",
})

# Kerberos delegation.
DELEGATION_EDGES: frozenset[str] = frozenset({
    "AllowedToDelegate", "AllowedToAct", "AddAllowedToAct", "CoerceToTGT",
})

# AD CS abuse.
ADCS_EDGES: frozenset[str] = frozenset({
    "Enroll", "ManageCA", "ManageCertificates", "GoldenCert", "WritePKIEnrollmentFlag",
    "WritePKINameFlag", "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC6a", "ADCSESC6b",
    "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13",
})

# NTLM relay / coercion.
COERCION_EDGES: frozenset[str] = frozenset({
    "CoerceAndRelayNTLMToSMB", "CoerceAndRelayNTLMToLDAP", "CoerceAndRelayNTLMToLDAPS",
    "CoerceAndRelayNTLMToADCS",
})

# Rights that let the holder edit a GPO (and so run code on everything it applies to).
GPO_EDIT_EDGES: frozenset[str] = frozenset({
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "OwnsLimitedRights", "WriteOwnerLimitedRights",
})

# Code execution / logon rights on computers.
EXEC_EDGES: frozenset[str] = frozenset({"AdminTo", "CanRDP", "ExecuteDCOM", "CanPSRemote", "SQLAdmin"})

# Domain trust relationships (`A -[trust]-> B`: A trusts B, principals of B can access A).
TRUST_EDGES: frozenset[str] = frozenset({"SameForestTrust", "CrossForestTrust"})
# Trust edges BloodHound adds when a trust's configuration is abusable.
TRUST_ABUSE_EDGES: frozenset[str] = frozenset({"SpoofSIDHistory", "AbuseTGTDelegation"})

# Everything shown by the `outbound` / `inbound` views.
CONTROL_EDGES: frozenset[str] = ACL_EDGES | CREDENTIAL_EDGES | DELEGATION_EDGES | ADCS_EDGES | COERCION_EDGES

# Edges BloodHound treats as traversable for attack-path finding.
TRAVERSABLE_EDGES: frozenset[str] = (
    (CONTROL_EDGES - {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet", "Enroll", "ManageCA",
                      "ManageCertificates", "WritePKIEnrollmentFlag", "WritePKINameFlag"})
    | EXEC_EDGES | TRUST_EDGES | TRUST_ABUSE_EDGES
    | {MEMBER_OF, HAS_SESSION, CONTAINS, GP_LINK, "DCFor", "WriteSPN"}
)

# Hops that need no action: rights flow along them by themselves.
PASSIVE_EDGES: frozenset[str] = frozenset({MEMBER_OF, CONTAINS, GP_LINK, "DCFor"})

# Names accepted by `path --exclude` for groups of edges.
EDGE_GROUPS: dict[str, frozenset[str]] = {
    "sessions": frozenset({HAS_SESSION}),
    "acl": ACL_EDGES,
    "exec": EXEC_EDGES,
    "delegation": DELEGATION_EDGES,
    "adcs": (ADCS_EDGES | {"CoerceAndRelayNTLMToADCS"}) & TRAVERSABLE_EDGES,
    "relay": COERCION_EDGES,
    "trusts": TRUST_EDGES | TRUST_ABUSE_EDGES,
}

Severity = Literal["critical", "high", "medium", "low"]
SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low")  # worst first

_CRITICAL = frozenset({
    "GenericAll", "WriteDacl", "WriteOwner", "Owns", "DCSync", "GetChangesAll", "AllExtendedRights",
    "AdminTo", "GoldenCert", "ADCSESC1", "ADCSESC3", "ADCSESC4", "ADCSESC6a", "ADCSESC6b",
    "ADCSESC9a", "ADCSESC9b", "ADCSESC10a", "ADCSESC10b", "ADCSESC13", "HasSIDHistory",
})
_HIGH = frozenset({
    "GenericWrite", "ForceChangePassword", "AddMember", "AddSelf", "AddKeyCredentialLink",
    "ReadLAPSPassword", "ReadGMSAPassword", "SyncLAPSPassword", "DumpSMSAPassword",
    "AllowedToDelegate", "AllowedToAct", "AddAllowedToAct", "WriteAccountRestrictions",
    "CanPSRemote", "SQLAdmin", "WriteGPLink", "ManageCA", "CoerceToTGT",
    *COERCION_EDGES,
})


def severity(edge: str) -> Severity:
    """Rough offensive impact of an edge, used for colouring."""
    if edge in _CRITICAL:
        return "critical"
    if edge in _HIGH:
        return "high"
    return "medium"


def severity_rank(edge: str) -> int:
    """Sort key: 0 for critical edges, 1 for high, 2 for medium."""
    return SEVERITIES.index(severity(edge))
