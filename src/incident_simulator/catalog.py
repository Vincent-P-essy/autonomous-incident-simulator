"""Closed catalog of inert simulation primitives.

Primitives describe state transitions and telemetry templates only. They expose no
hook for operating-system processes, network clients, scripts, or arbitrary text.
"""

from __future__ import annotations

from typing import Dict, Iterable, Tuple

from .models import Primitive, PrimitiveTelemetry


def _event(
    source: str, event_type: str, outcome: str = "success", **attributes: object
) -> PrimitiveTelemetry:
    return PrimitiveTelemetry(
        source=source,
        event_type=event_type,
        outcome=outcome,
        attributes=tuple(sorted(attributes.items())),
    )


_PRIMITIVES: Tuple[Primitive, ...] = (
    Primitive(
        id="social.spearphishing_link",
        title="Simulated spearphishing link interaction",
        technique_id="T1566.002",
        technique_name="Phishing: Spearphishing Link",
        tactic="initial-access",
        requires=("entry.ready",),
        effects=("social.lure_opened",),
        capabilities=("simulated_only", "social_engineering"),
        min_duration_seconds=35,
        max_duration_seconds=95,
        telemetry=(
            _event(
                "email_gateway", "message_delivered", campaign="training-simulation"
            ),
            _event(
                "web_proxy", "link_opened", destination_class="documentation-domain"
            ),
        ),
    ),
    Primitive(
        id="credential.session_cookie",
        title="Simulated browser session token exposure",
        technique_id="T1539",
        technique_name="Steal Web Session Cookie",
        tactic="credential-access",
        requires=("social.lure_opened",),
        effects=("credential.obtained",),
        capabilities=("simulated_only", "credential_access"),
        min_duration_seconds=15,
        max_duration_seconds=45,
        telemetry=(
            _event(
                "endpoint", "browser_session_access", classification="synthetic-token"
            ),
            _event("identity", "session_anomaly", risk="medium"),
        ),
    ),
    Primitive(
        id="credential.password_spray",
        title="Simulated low-rate password spray",
        technique_id="T1110.003",
        technique_name="Brute Force: Password Spraying",
        tactic="credential-access",
        requires=("entry.ready",),
        effects=("credential.obtained",),
        capabilities=("simulated_only", "credential_access", "authentication_testing"),
        min_duration_seconds=90,
        max_duration_seconds=180,
        telemetry=(
            _event("identity", "authentication_failure", reason="invalid-credential"),
            _event("identity", "authentication_failure", reason="invalid-credential"),
            _event("identity", "authentication_failure", reason="invalid-credential"),
            _event("identity", "authentication_success", risk="high"),
        ),
    ),
    Primitive(
        id="identity.valid_account",
        title="Simulated authentication with an exposed account",
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="defense-evasion",
        requires=("credential.obtained",),
        effects=("identity.authenticated",),
        capabilities=("simulated_only", "authentication"),
        min_duration_seconds=8,
        max_duration_seconds=22,
        telemetry=(
            _event("identity", "authentication_success", risk="high"),
            _event("identity", "new_session", trust="unmanaged"),
        ),
    ),
    Primitive(
        id="discovery.network_services",
        title="Simulated network service discovery",
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="discovery",
        requires=("identity.authenticated",),
        effects=("network.service_known",),
        capabilities=("simulated_only", "discovery"),
        min_duration_seconds=20,
        max_duration_seconds=65,
        telemetry=(
            _event("network", "service_probe", scope="single-target"),
            _event("firewall", "connection_allowed", rule="simulation-lab"),
        ),
    ),
    Primitive(
        id="discovery.network_shares",
        title="Simulated network share discovery",
        technique_id="T1135",
        technique_name="Network Share Discovery",
        tactic="discovery",
        requires=("identity.authenticated",),
        effects=("network.share_known",),
        capabilities=("simulated_only", "discovery"),
        min_duration_seconds=18,
        max_duration_seconds=50,
        telemetry=(
            _event("network", "share_enumeration", scope="single-target"),
            _event("file_audit", "share_listed", sensitivity="internal"),
        ),
    ),
    Primitive(
        id="lateral.ssh_valid_account",
        title="Simulated SSH access with a valid account",
        technique_id="T1021.004",
        technique_name="Remote Services: SSH",
        tactic="lateral-movement",
        requires=("identity.authenticated", "network.service_known"),
        effects=("access.target",),
        capabilities=("simulated_only", "lateral_movement"),
        min_duration_seconds=10,
        max_duration_seconds=30,
        telemetry=(
            _event("network", "remote_service_connection", service="ssh"),
            _event(
                "linux_audit", "remote_login", authentication="public-key-simulated"
            ),
        ),
    ),
    Primitive(
        id="lateral.smb_valid_account",
        title="Simulated SMB access with a valid account",
        technique_id="T1021.002",
        technique_name="Remote Services: SMB/Windows Admin Shares",
        tactic="lateral-movement",
        requires=("identity.authenticated", "network.share_known"),
        effects=("access.target",),
        capabilities=("simulated_only", "lateral_movement"),
        min_duration_seconds=12,
        max_duration_seconds=35,
        telemetry=(
            _event("network", "remote_service_connection", service="smb"),
            _event(
                "file_audit", "share_session_opened", authentication="simulated-account"
            ),
        ),
    ),
    Primitive(
        id="access.public_application",
        title="Simulated public application access boundary failure",
        technique_id="T1190",
        technique_name="Exploit Public-Facing Application",
        tactic="initial-access",
        requires=("entry.ready",),
        effects=("access.target",),
        capabilities=("simulated_only", "application_access"),
        min_duration_seconds=25,
        max_duration_seconds=70,
        telemetry=(
            _event(
                "web_gateway", "application_boundary_violation", validation="synthetic"
            ),
            _event("web_app", "unexpected_privileged_response", status=200),
        ),
    ),
    Primitive(
        id="discovery.local_accounts",
        title="Simulated local account discovery",
        technique_id="T1087",
        technique_name="Account Discovery",
        tactic="discovery",
        requires=("access.target",),
        effects=("identity.accounts_discovered",),
        capabilities=("simulated_only", "discovery"),
        min_duration_seconds=8,
        max_duration_seconds=24,
        telemetry=(
            _event("application_audit", "account_directory_read", record_count=7),
            _event("siem", "account_discovery_signal", confidence="medium"),
        ),
    ),
    Primitive(
        id="collection.local_records",
        title="Simulated collection of target business records",
        technique_id="T1005",
        technique_name="Data from Local System",
        tactic="collection",
        requires=("access.target",),
        effects=(
            "data.collected",
            "objective.asset_compromised",
            "objective.data_collected",
        ),
        capabilities=("simulated_only", "collection"),
        min_duration_seconds=15,
        max_duration_seconds=55,
        telemetry=(
            _event("application_audit", "sensitive_records_read", records=24),
            _event("siem", "bulk_read_signal", confidence="high"),
        ),
    ),
)


CATALOG: Dict[str, Primitive] = {primitive.id: primitive for primitive in _PRIMITIVES}


def all_primitives() -> Tuple[Primitive, ...]:
    return _PRIMITIVES


def get_primitive(primitive_id: str) -> Primitive:
    return CATALOG[primitive_id]


def known_event_types(primitive_ids: Iterable[str]) -> Tuple[str, ...]:
    values = {
        template.event_type
        for primitive_id in primitive_ids
        for template in CATALOG[primitive_id].telemetry
    }
    return tuple(sorted(values))


def known_sources(primitive_ids: Iterable[str]) -> Tuple[str, ...]:
    values = {
        template.source
        for primitive_id in primitive_ids
        for template in CATALOG[primitive_id].telemetry
    }
    return tuple(sorted(values))
