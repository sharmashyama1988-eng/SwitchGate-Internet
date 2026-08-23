"""
SwitchGate - Unified Firewall Rules Engine Proxy
Aliases to the authoritative firewall subsystem in root firewall.rules_engine.
"""
from firewall.rules_engine import (
    FirewallRulesEngine,
    rules_engine,
    DEFAULT_RULES,
    RULES_FILE
)

__all__ = ["FirewallRulesEngine", "rules_engine", "DEFAULT_RULES", "RULES_FILE"]
