"""Policy and portal configuration services."""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import yaml

from ..errors import PortalError
from ..schemas import PolicyConfigCreate
from ..settings import MGMT_PLANE_AGENT_KEY, PortalSettings
from ..storage.base import PolicyConfigStore

logger = logging.getLogger("aim-portal.services.policy")

MAX_POLICY_CONFIGS = 50
MAX_CONFIG_YAML_BYTES = 102_400


class PolicyService:
    """Encapsulates RBAC policy and mTLS helper logic."""

    def __init__(self, settings, admin_client, policy_store):
        # type: (PortalSettings, Any, PolicyConfigStore) -> None
        self.settings = settings
        self.admin_client = admin_client
        self.policy_store = policy_store

    def get_agent_spiffe_id(self, agent_key):
        # type: (str) -> str
        if agent_key == MGMT_PLANE_AGENT_KEY:
            return self.settings.control_plane.spiffe_id or "spiffe://{0}/ests/bp/placeholder/aid/{1}".format(
                self.settings.trust_domain,
                agent_key,
            )
        agent = self.settings.agents.get(agent_key)
        if not agent:
            return "spiffe://{0}/ests/bp/placeholder/aid/{1}".format(self.settings.trust_domain, agent_key)
        return agent.spiffe_id or "spiffe://{0}/ests/bp/placeholder/aid/{1}".format(
            self.settings.trust_domain,
            agent_key,
        )

    def get_control_plane_spiffe_id(self):
        # type: () -> str
        return self.get_agent_spiffe_id(MGMT_PLANE_AGENT_KEY)

    @staticmethod
    def sanitize_config_name(name):
        # type: (str) -> str
        clean = re.sub(r"[^a-zA-Z0-9_-]", "-", name.strip())
        return clean[:64]

    def is_caller_agent(self, agent_key):
        # type: (str) -> bool
        agent = self.settings.agents.get(agent_key)
        if not agent:
            return False
        role = (agent.role or "").lower()
        return "protected" not in role and "resource" not in role and "mcp server" not in role

    def ensure_control_plane_in_mtls(self, ids):
        # type: (List[str]) -> List[str]
        result = list(ids)
        control_plane_id = self.get_control_plane_spiffe_id()
        if control_plane_id and control_plane_id not in result:
            result.append(control_plane_id)
        return result

    def entry_matches_control_plane(self, entry):
        # type: (Dict[str, Any]) -> bool
        if not isinstance(entry, dict):
            return False
        markers = [
            MGMT_PLANE_AGENT_KEY,
            self.settings.control_plane.app_name,
            self.settings.control_plane.name,
            self.settings.control_plane.spiffe_id,
            self.settings.control_plane.entra_agent_id,
        ]
        fields = [
            str(entry.get("name", "")),
            str(entry.get("spiffe_id", "")),
            str(entry.get("spiffe_id_prefix", "")),
            str(entry.get("description", "")),
            str(entry.get("entra_agent_id", "")),
        ]
        for marker in markers:
            if marker and any(marker in field for field in fields if field):
                return True
        return False

    def ensure_control_plane_policy(self, policy_doc):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        if not isinstance(policy_doc, dict):
            return policy_doc
        policies = policy_doc.setdefault("policies", [])
        idx = None
        for index, entry in enumerate(policies):
            if self.entry_matches_control_plane(entry):
                idx = index
                break
        desired_rules = [{"path": "/mgmt/*", "methods": ["GET", "PUT"], "action": "allow"}]
        if idx is None:
            policies.append(
                {
                    "name": MGMT_PLANE_AGENT_KEY,
                    "description": self.settings.control_plane.role or "Dedicated management service",
                    "spiffe_id": self.settings.control_plane.spiffe_id,
                    "entra_agent_id": self.settings.control_plane.entra_agent_id,
                    "ca": {
                        "agent_state": "enabled",
                        "agent_tag": "admin",
                        "skip_target_tag_check": True,
                    },
                    "rules": desired_rules,
                }
            )
            return policy_doc
        entry = policies[idx]
        entry.setdefault("name", MGMT_PLANE_AGENT_KEY)
        entry.setdefault("description", self.settings.control_plane.role or "Dedicated management service")
        if not entry.get("spiffe_id") and self.settings.control_plane.spiffe_id:
            entry["spiffe_id"] = self.settings.control_plane.spiffe_id
            entry.pop("spiffe_id_prefix", None)
        if not entry.get("entra_agent_id") and self.settings.control_plane.entra_agent_id:
            entry["entra_agent_id"] = self.settings.control_plane.entra_agent_id
        if not isinstance(entry.get("ca"), dict):
            entry["ca"] = {}
        entry["ca"].setdefault("agent_state", "enabled")
        entry["ca"].setdefault("agent_tag", "admin")
        entry["ca"]["skip_target_tag_check"] = True
        entry["rules"] = self.merge_rules(entry.get("rules", []), desired_rules)
        return policy_doc

    def hydrate_policy_identities(self, policy_doc):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        if not isinstance(policy_doc, dict):
            return policy_doc
        policies = policy_doc.get("policies", [])
        if not isinstance(policies, list):
            return policy_doc
        generic_prefix = "spiffe://{0}/ests/bp/".format(self.settings.trust_domain)
        for entry in policies:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name", "")
            if name == MGMT_PLANE_AGENT_KEY:
                spiffe_id = self.settings.control_plane.spiffe_id
                entra_id = self.settings.control_plane.entra_agent_id
            else:
                agent = self.settings.agents.get(name)
                spiffe_id = agent.spiffe_id if agent else ""
                entra_id = agent.entra_agent_id if agent else ""
            current_prefix = str(entry.get("spiffe_id_prefix", "") or "")
            current_exact = str(entry.get("spiffe_id", "") or "")
            if spiffe_id and not current_exact and (not current_prefix or current_prefix == generic_prefix):
                entry["spiffe_id"] = spiffe_id
                entry.pop("spiffe_id_prefix", None)
            if entra_id and not entry.get("entra_agent_id"):
                entry["entra_agent_id"] = entra_id
        return policy_doc

    @staticmethod
    def normalize_methods(methods):
        # type: (List[str]) -> List[str]
        return sorted([str(method).upper() for method in (methods or [])])

    def rule_sig(self, rule):
        # type: (Dict[str, Any]) -> tuple
        return (
            str(rule.get("path", "")),
            tuple(self.normalize_methods(rule.get("methods", []))),
            str(rule.get("action", "")),
            bool(rule.get("require_jwt", False)),
            tuple(sorted(str(role) for role in (rule.get("required_roles") or []))),
        )

    @staticmethod
    def path_overlaps(path_a, path_b):
        # type: (str, str) -> bool
        if not path_a or not path_b:
            return False
        if path_a == path_b:
            return True
        prefix_a = path_a[:-1] if path_a.endswith("/*") else ""
        prefix_b = path_b[:-1] if path_b.endswith("/*") else ""
        if prefix_a and (path_b.startswith(prefix_a) or path_b == prefix_a[:-1]):
            return True
        if prefix_b and (path_a.startswith(prefix_b) or path_a == prefix_b[:-1]):
            return True
        return False

    def methods_overlap(self, methods_a, methods_b):
        # type: (List[str], List[str]) -> bool
        set_a = set(self.normalize_methods(methods_a))
        set_b = set(self.normalize_methods(methods_b))
        if "*" in set_a or "*" in set_b:
            return True
        return bool(set_a.intersection(set_b))

    def rules_overlap(self, rule_a, rule_b):
        # type: (Dict[str, Any], Dict[str, Any]) -> bool
        return self.path_overlaps(rule_a.get("path", ""), rule_b.get("path", "")) and self.methods_overlap(
            rule_a.get("methods", []),
            rule_b.get("methods", []),
        )

    def merge_rules(self, existing_rules, desired_rules):
        # type: (List[Dict[str, Any]], List[Dict[str, Any]]) -> List[Dict[str, Any]]
        existing_by_sig = {}
        for rule in existing_rules or []:
            existing_by_sig[self.rule_sig(rule)] = rule
        desired_sigs = set()
        merged = []
        for desired in desired_rules:
            sig = self.rule_sig(desired)
            desired_sigs.add(sig)
            merged.append(existing_by_sig.get(sig, desired))
        for rule in existing_rules or []:
            sig = self.rule_sig(rule)
            if sig not in desired_sigs:
                overlaps = any(self.rules_overlap(rule, desired) for desired in desired_rules)
                if not overlaps:
                    merged.append(rule)
        return merged

    def find_or_create_agent_policy(self, policies, agent_name, spiffe_id, description):
        # type: (List[Dict[str, Any]], str, str, str) -> int
        for index, entry in enumerate(policies):
            if self.is_agent_policy(entry, agent_name):
                return index
        policies.append({"spiffe_id": spiffe_id, "name": agent_name, "description": description, "rules": []})
        return len(policies) - 1

    @staticmethod
    def is_agent_policy(entry, agent_name):
        # type: (Dict[str, Any], str) -> bool
        if entry.get("name", "") == agent_name:
            return True
        for field in ("spiffe_id", "spiffe_id_prefix"):
            if agent_name in str(entry.get(field, "")):
                return True
        return False

    def desired_agent_specs(self):
        # type: () -> List[Dict[str, Any]]
        specs = [
            {
                "name": "budget-report",
                "description": "Read-only access to budget data",
                "ca": {
                    "agent_state": "enabled",
                    "agent_tag": "Finance",
                    "blocked_risk_levels": ["high"],
                },
                "rules": [
                    {"path": "/budget/read", "methods": ["GET", "POST"], "action": "allow", "require_jwt": True, "required_roles": ["Budget.Read"]},
                    {
                        "path": "/budget/submit",
                        "methods": ["POST"],
                        "action": "deny",
                        "permissive": {
                            "require_jwt": True,
                            "required_roles": ["Budget.Submit"],
                        },
                    },
                    {"path": "/budget/*", "methods": ["*"], "action": "deny"},
                ],
            },
            {
                "name": "employee-menus",
                "description": "No network/STS access - blocked at mTLS + CA tag layers",
                "ca": {
                    "agent_state": "enabled",
                    "agent_tag": "HR",
                    "blocked_risk_levels": ["high"],
                },
                "rules": [{"path": "/*", "methods": ["*"], "action": "deny"}],
            },
            {
                "name": "budget-approval",
                "description": "Can read and submit budgets + management access",
                "ca": {
                    "agent_state": "enabled",
                    "agent_tag": "Finance",
                    "blocked_risk_levels": ["high"],
                },
                "rules": [
                    {"path": "/budget/read", "methods": ["GET", "POST"], "action": "allow", "require_jwt": True, "required_roles": ["Budget.Read"]},
                    {"path": "/budget/submit", "methods": ["POST"], "action": "allow", "require_jwt": True, "required_roles": ["Budget.Submit"]},
                ],
            },
            {
                "name": MGMT_PLANE_AGENT_KEY,
                "description": "Dedicated management service",
                "ca": {
                    "agent_state": "enabled",
                    "agent_tag": "Operations",
                    "blocked_risk_levels": ["high"],
                    "skip_target_tag_check": True,
                },
                "rules": [{"path": "/mgmt/*", "methods": ["GET", "PUT"], "action": "allow"}],
            },
        ]
        known_names = {item["name"] for item in specs}
        for agent_key in self.settings.agents:
            if agent_key in known_names or agent_key == "budget-backend":
                continue
            specs.append(
                {
                    "name": agent_key,
                    "description": "{0} - default deny (dynamic agent)".format(self.settings.agents[agent_key].name),
                    "rules": [{"path": "/*", "methods": ["*"], "action": "deny"}],
                }
            )
        return specs

    def build_permissive_rbac_yaml(self):
        # type: () -> str
        policy = {
            "version": "5.0-permissive",
            "trust_domain": self.settings.trust_domain,
            "default_action": "allow",
            "admin_governance": {
                "enabled": True,
                "target_agent_tag": "finance",
                "risk_enforcement": "sts",
            },
            "policies": [],
        }
        for spec in self.desired_agent_specs():
            spiffe_id = self.get_agent_spiffe_id(spec["name"])
            entry = {
                "spiffe_id_prefix": spiffe_id,
                "name": spec["name"],
                "description": spec.get("description", spec["name"]),
            }
            if "ca" in spec:
                entry["ca"] = dict(spec["ca"])
            # Permissive: all RBAC rules are allow, but JWT is still enforced
            entry["rules"] = []
            for rule in spec["rules"]:
                permissive = rule.get("permissive", {})
                require_jwt = permissive.get("require_jwt", rule.get("require_jwt"))
                required_roles = permissive.get("required_roles", rule.get("required_roles"))
                if required_roles:
                    require_jwt = True

                yaml_rule = {
                    "path": rule["path"],
                    "methods": rule["methods"],
                    "action": permissive.get("action", "allow"),
                }
                if require_jwt:
                    yaml_rule["require_jwt"] = True
                if required_roles:
                    yaml_rule["required_roles"] = required_roles
                entry["rules"].append(yaml_rule)
            policy["policies"].append(entry)
        return yaml.safe_dump(policy, sort_keys=False, default_flow_style=False, indent=2)

    def build_hardened_rbac_yaml(self):
        # type: () -> str
        policy = {
            "version": "5.0",
            "trust_domain": self.settings.trust_domain,
            "default_action": "deny",
            "admin_governance": {
                "enabled": True,
                "target_agent_tag": "finance",
                "risk_enforcement": "sts",
            },
            "policies": [],
        }
        for spec in self.desired_agent_specs():
            spiffe_id = self.get_agent_spiffe_id(spec["name"])
            entry = {
                "spiffe_id_prefix": spiffe_id,
                "name": spec["name"],
                "description": spec["description"],
            }
            if spec.get("entra_agent_id"):
                entry["entra_agent_id"] = spec["entra_agent_id"]
            if "ca" in spec:
                entry["ca"] = dict(spec["ca"])
            entry["rules"] = []
            for rule in spec["rules"]:
                yaml_rule = {"path": rule["path"], "methods": rule["methods"], "action": rule["action"]}
                if rule.get("require_jwt"):
                    yaml_rule["require_jwt"] = True
                if rule.get("required_roles"):
                    yaml_rule["required_roles"] = rule["required_roles"]
                entry["rules"].append(yaml_rule)
            policy["policies"].append(entry)
        return yaml.safe_dump(policy, sort_keys=False, default_flow_style=False, indent=2)

    def harden_policy_additive(self, current_policy):
        # type: (Dict[str, Any]) -> Dict[str, Any]
        policy = {
            "version": current_policy.get("version", "4.0"),
            "trust_domain": current_policy.get("trust_domain", self.settings.trust_domain),
            "default_action": "deny",
            "policies": list(current_policy.get("policies", [])),
        }
        for spec in self.desired_agent_specs():
            idx = self.find_or_create_agent_policy(
                policy["policies"],
                spec["name"],
                self.get_agent_spiffe_id(spec["name"]),
                spec["description"],
            )
            policy["policies"][idx]["rules"] = self.merge_rules(
                policy["policies"][idx].get("rules", []),
                spec["rules"],
            )
        return self.ensure_control_plane_policy(policy)

    async def get_policy(self, request_id):
        # type: (str) -> Dict[str, Any]
        return await self.admin_client.get_json("policy", request_id)

    async def put_policy(self, yaml_text, request_id):
        # type: (str, str) -> Dict[str, Any]
        policy_doc = None
        try:
            policy_doc = yaml.safe_load(yaml_text)
        except Exception:
            policy_doc = None
        if policy_doc and isinstance(policy_doc, dict):
            policy_doc = self.hydrate_policy_identities(policy_doc)
            policy_doc = self.ensure_control_plane_policy(policy_doc)
            # Remove empty spiffe_id when spiffe_id_prefix is set
            # (sidecar rejects having both, even when spiffe_id is empty string)
            for cp in policy_doc.get("policies", []):
                if not cp.get("spiffe_id") and cp.get("spiffe_id_prefix"):
                    cp.pop("spiffe_id", None)
            yaml_text = yaml.safe_dump(policy_doc, sort_keys=False, default_flow_style=False, indent=2)
        return await self.admin_client.put_yaml("policy", yaml_text, request_id)

    async def get_mtls_policy(self, request_id):
        # type: (str) -> Dict[str, Any]
        return await self.admin_client.get_json("mtls-policy", request_id)

    async def put_mtls_policy(self, allowed_ids, request_id):
        # type: (List[str], str) -> Dict[str, Any]
        guarded = self.ensure_control_plane_in_mtls(list(allowed_ids))
        return await self.admin_client.put_json("mtls-policy", {"allowed_ids": guarded}, request_id)

    async def get_audit(self, request_id):
        # type: (str) -> Any
        data = await self.admin_client.get_json("audit", request_id)
        if isinstance(data, dict) and "entries" in data:
            return data.get("entries", [])
        return data

    async def get_metrics(self, request_id):
        # type: (str) -> Dict[str, Any]
        return await self.admin_client.get_json("metrics", request_id)

    async def get_oauth_status(self, request_id):
        # type: (str) -> Dict[str, Any]
        return await self.admin_client.get_json("oauth-status", request_id)

    async def list_policy_configs(self):
        # type: () -> List[Dict[str, Any]]
        return await self.policy_store.list_configs()

    async def save_policy_config(self, payload):
        # type: (PolicyConfigCreate) -> Dict[str, str]
        name = self.sanitize_config_name(payload.name)
        if not name:
            raise PortalError(400, "invalid_name", "Name contains only invalid characters")
        if len(payload.yaml.encode("utf-8")) > MAX_CONFIG_YAML_BYTES:
            raise PortalError(413, "payload_too_large", "YAML body exceeds 100KB limit")
        configs = await self.policy_store.list_configs()
        now = datetime.now(timezone.utc).isoformat()
        entry = {
            "name": name,
            "yaml": payload.yaml,
            "description": str(payload.description)[:256],
            "created_at": now,
            "updated_at": now,
        }
        existing_idx = None
        for index, config in enumerate(configs):
            if config.get("name") == name:
                existing_idx = index
                break
        if existing_idx is not None:
            entry["created_at"] = configs[existing_idx].get("created_at", now)
            configs[existing_idx] = entry
        else:
            if len(configs) >= MAX_POLICY_CONFIGS:
                raise PortalError(400, "config_limit_reached", "Maximum saved configurations reached")
            configs.append(entry)
        await self.policy_store.write_configs(configs)
        return {"status": "saved", "name": name}

    async def delete_policy_config(self, name):
        # type: (str) -> Dict[str, str]
        if len(name) > 128:
            raise PortalError(400, "invalid_name", "Name too long")
        sanitized = self.sanitize_config_name(name)
        configs = await self.policy_store.list_configs()
        new_configs = [config for config in configs if config.get("name") != sanitized]
        if len(new_configs) == len(configs):
            raise PortalError(404, "config_not_found", "Configuration '{0}' not found".format(sanitized))
        await self.policy_store.write_configs(new_configs)
        return {"status": "deleted", "name": sanitized}

    def get_identity_mapping(self):
        # type: () -> Dict[str, Any]
        mapping = []
        for agent_key, agent in self.settings.agents.items():
            mapping.append(
                {
                    "agent_name": agent.name,
                    "agent_key": agent_key,
                    "entra_agent_id": agent.entra_agent_id or None,
                    "spiffe_id": agent.spiffe_id or self.get_agent_spiffe_id(agent_key),
                    "role": agent.role,
                    "entra_bridged": bool(agent.entra_agent_id and agent.entra_agent_id != "pending-entra-creation"),
                }
            )
        return {
            "trust_domain": self.settings.trust_domain,
            "mapping": mapping,
            "all_entra_bridged": all(item["entra_bridged"] for item in mapping) if mapping else True,
        }

    def evaluate_policy(self, policy_doc, agent_key, method, path):
        # type: (Dict[str, Any], str, str, str) -> Dict[str, Any]
        default_action = str(policy_doc.get("default_action", "deny")).lower()
        entry = None
        for policy_entry in policy_doc.get("policies", []):
            if self.is_agent_policy(policy_entry, agent_key):
                entry = policy_entry
                break
        if not entry:
            return {"action": default_action, "rule": None}
        for rule in entry.get("rules", []):
            rule_path = str(rule.get("path", ""))
            rule_methods = self.normalize_methods(rule.get("methods", []))
            method_match = "*" in rule_methods or method.upper() in rule_methods
            path_match = rule_path == path or (rule_path.endswith("/*") and path.startswith(rule_path[:-1]))
            if method_match and path_match:
                return {"action": str(rule.get("action", default_action)).lower(), "rule": rule}
        return {"action": default_action, "rule": None}

    def build_enforcement_matrix(self, mtls_policy, policy_doc, ca_status):
        # type: (Dict[str, Any], Dict[str, Any], Dict[str, Any]) -> List[Dict[str, Any]]
        matrix = []
        number = 1
        allowed_ids = set(mtls_policy.get("allowed_ids", []))
        ca_by_key = {}
        for item in ca_status.get("agents", []):
            ca_by_key[item.get("key", "")] = item

        for agent_key, agent in self.settings.agents.items():
            if not self.is_caller_agent(agent_key):
                continue
            sid = self.get_agent_spiffe_id(agent_key)
            if sid not in allowed_ids:
                matrix.append(
                    {
                        "num": number,
                        "caller": agent.name,
                        "target": "BudgetBackend",
                        "request": "Any request",
                        "result": "🚫 BLOCKED",
                        "layer": "mTLS handshake rejected",
                    }
                )
                number += 1
                continue
            read_decision = self.evaluate_policy(policy_doc, agent_key, "GET", "/budget/read")
            matrix.append(
                {
                    "num": number,
                    "caller": agent.name,
                    "target": "BudgetBackend",
                    "request": "GET /budget/read",
                    "result": "✅ ALLOW" if read_decision["action"] == "allow" else "❌ 403",
                    "layer": "mTLS + RBAC" if read_decision["action"] == "allow" else "RBAC deny",
                }
            )
            number += 1
            if agent_key in ("budget-report", "budget-approval"):
                submit_decision = self.evaluate_policy(policy_doc, agent_key, "POST", "/budget/submit")
                matrix.append(
                    {
                        "num": number,
                        "caller": agent.name,
                        "target": "BudgetBackend",
                        "request": "POST /budget/submit",
                        "result": "✅ ALLOW" if submit_decision["action"] == "allow" else "❌ 403",
                        "layer": "mTLS + RBAC" if submit_decision["action"] == "allow" else "RBAC deny",
                    }
                )
                number += 1

        target = ca_by_key.get("budget-approval")
        if target:
            target_tag = target.get("agent_tag", "")
            blocked_levels = set(target.get("blocked_risk_levels", []))
            for agent_key, agent in self.settings.agents.items():
                if agent_key == "budget-approval" or not self.is_caller_agent(agent_key):
                    continue
                caller = ca_by_key.get(agent_key, {})
                state = caller.get("agent_state", "enabled")
                risk = caller.get("current_risk", "low")
                caller_tag = caller.get("agent_tag", "")
                if state != "enabled":
                    result = "❌ 403"
                    layer = "A2A (agent disabled)"
                elif risk in blocked_levels:
                    result = "❌ 403"
                    layer = "A2A (risk blocked)"
                elif caller_tag != target_tag:
                    result = "❌ 403"
                    layer = "A2A (tag mismatch)"
                else:
                    result = "✅ ALLOW"
                    layer = "A2A (JWT + CA)"
                matrix.append(
                    {
                        "num": number,
                        "caller": agent.name,
                        "target": target.get("name", "BudgetApproval"),
                        "request": "GET /a2a/status",
                        "result": result,
                        "layer": layer,
                    }
                )
                number += 1

        for agent_key, agent in self.settings.agents.items():
            caller = ca_by_key.get(agent_key, {})
            blocked_levels = set(caller.get("blocked_risk_levels", []))
            risk = caller.get("current_risk", "")
            sid = self.get_agent_spiffe_id(agent_key)
            if risk and risk in blocked_levels and sid in allowed_ids:
                matrix.append(
                    {
                        "num": number,
                        "caller": "{0}*".format(agent.name),
                        "target": "BudgetBackend",
                        "request": "GET /budget/read",
                        "result": "❌ 403",
                        "layer": "CA (current risk blocked)",
                    }
                )
                number += 1
        return matrix
