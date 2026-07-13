"""Domain-specific failures with user-facing diagnostics."""


class IncidentSimulatorError(Exception):
    """Base error for expected simulator failures."""


class ValidationError(IncidentSimulatorError):
    """The scenario DSL is invalid or unsafe."""


class PlanningError(IncidentSimulatorError):
    """No safe plan satisfies the declared constraints."""
