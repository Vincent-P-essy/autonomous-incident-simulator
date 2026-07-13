# Security policy

## Supported version

The current `0.1.x` line receives security fixes while this repository remains
under active development.

## Reporting a vulnerability

Do not publish an issue containing exploit details, credentials, or sensitive
telemetry. Use GitHub's private security-advisory reporting channel for this
repository. Include the affected version, reproduction conditions, impact, and a
minimal inert proof when possible.

## Responsible-use boundary

This project accepts only synthetic scenarios and catalog identifiers. Reports and
documentation must not contain live credentials, personal data, private addresses,
or instructions targeting systems without explicit authorization.

Contributions that introduce process execution, real target communication,
unbounded dynamic loading, or a bypass around the catalog require a new threat
model and are outside the current safety architecture.

## Operational guidance

- Keep the API bound to loopback or place it behind an authenticated trusted proxy.
- Treat exported reports as potentially sensitive exercise material.
- Run containers with the included capability, filesystem, and resource controls.
- Review ATT&CK mappings and all new primitive telemetry before publishing a dataset.
