"""Deterministic generation of inert enterprise topologies."""

from __future__ import annotations

import hashlib
from typing import Dict, List, Tuple, cast

from .errors import ValidationError
from .models import Asset, Identity, NetworkFlow, Topology, TopologyRequest


_ROLE_TEMPLATES: Dict[str, Dict[str, object]] = {
    "user-workstation": {
        "prefix": "ws",
        "operating_system": "Windows 11 (simulated)",
        "zone": "user",
        "criticality": "medium",
        "services": ("https",),
    },
    "identity-provider": {
        "prefix": "idp",
        "operating_system": "Linux (simulated)",
        "zone": "management",
        "criticality": "critical",
        "services": ("https", "oidc"),
    },
    "siem": {
        "prefix": "siem",
        "operating_system": "Linux (simulated)",
        "zone": "management",
        "criticality": "high",
        "services": ("https", "syslog"),
    },
    "payroll-server": {
        "prefix": "payroll",
        "operating_system": "Linux (simulated)",
        "zone": "restricted",
        "criticality": "critical",
        "services": ("https", "ssh"),
    },
    "file-server": {
        "prefix": "files",
        "operating_system": "Windows Server (simulated)",
        "zone": "server",
        "criticality": "high",
        "services": ("smb",),
    },
    "public-web-app": {
        "prefix": "web",
        "operating_system": "Linux (simulated)",
        "zone": "dmz",
        "criticality": "high",
        "services": ("https",),
    },
    "backup-server": {
        "prefix": "backup",
        "operating_system": "Linux (simulated)",
        "zone": "backup",
        "criticality": "critical",
        "services": ("https",),
    },
}

_PROFILES: Dict[str, Tuple[str, ...]] = {
    "mixed-enterprise-small": (
        "user-workstation",
        "identity-provider",
        "siem",
        "backup-server",
    ),
    "linux-service-small": ("user-workstation", "identity-provider", "siem"),
    "web-application-small": ("identity-provider", "siem", "public-web-app"),
}

_ZONE_RANGES = {
    "user": "192.0.2.",
    "management": "198.51.100.",
    "server": "203.0.113.",
    "restricted": "203.0.113.",
    "dmz": "192.0.2.",
    "backup": "198.51.100.",
}


def supported_profiles() -> Tuple[str, ...]:
    return tuple(sorted(_PROFILES))


def supported_roles() -> Tuple[str, ...]:
    return tuple(sorted(_ROLE_TEMPLATES))


def profile_roles(profile: str) -> Tuple[str, ...]:
    try:
        return _PROFILES[profile]
    except KeyError as exc:
        raise ValidationError(f"unsupported topology profile: {profile}") from exc


def _stable_token(seed: int, *parts: str, size: int = 8) -> str:
    material = ":".join((str(seed),) + parts).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:size]


def generate_topology(request: TopologyRequest, seed: int) -> Topology:
    """Generate a topology containing only documentation-range addresses."""

    roles = list(profile_roles(request.profile))
    for role in request.required_roles:
        if role not in _ROLE_TEMPLATES:
            raise ValidationError(f"unsupported topology role: {role}")
        if role not in roles:
            roles.append(role)

    zone_counters: Dict[str, int] = {}
    assets: List[Asset] = []
    for role in roles:
        template = _ROLE_TEMPLATES[role]
        zone = str(template["zone"])
        zone_counters[zone] = zone_counters.get(zone, 9) + 1
        token = _stable_token(seed, request.profile, role)
        assets.append(
            Asset(
                id=f"asset-{token}",
                role=role,
                hostname=f"{template['prefix']}-{token[:6]}",
                operating_system=str(template["operating_system"]),
                zone=zone,
                address=f"{_ZONE_RANGES[zone]}{zone_counters[zone]}",
                criticality=str(template["criticality"]),
                services=cast(Tuple[str, ...], template["services"]),
            )
        )

    workstation = next(
        (asset for asset in assets if asset.role == "user-workstation"), assets[0]
    )
    identities = tuple(
        Identity(
            id=f"identity-{_stable_token(seed, 'identity', str(index), size=10)}",
            display_name=f"Synthetic Employee {index:03d}",
            privilege="standard" if index > 1 else "service-operator",
            home_asset_id=workstation.id,
        )
        for index in range(1, request.user_count + 1)
    )

    flows: List[NetworkFlow] = []
    for source in assets:
        for destination in assets:
            if source.id == destination.id:
                continue
            for service in destination.services:
                permitted = (
                    source.role == "user-workstation"
                    or source.role == "siem"
                    or destination.role in {"identity-provider", "siem"}
                )
                if permitted:
                    flows.append(
                        NetworkFlow(
                            source_asset_id=source.id,
                            destination_asset_id=destination.id,
                            service=service,
                            policy="simulated-allow",
                        )
                    )

    return Topology(
        profile=request.profile,
        assets=tuple(assets),
        identities=identities,
        allowed_flows=tuple(
            sorted(
                flows,
                key=lambda flow: (
                    flow.source_asset_id,
                    flow.destination_asset_id,
                    flow.service,
                ),
            )
        ),
    )


def find_asset_by_role(topology: Topology, role: str) -> Asset:
    matches = [asset for asset in topology.assets if asset.role == role]
    if not matches:
        raise ValidationError(
            f"topology does not contain objective target role: {role}"
        )
    return sorted(matches, key=lambda asset: asset.id)[0]
