"""Abstract storage interfaces."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class PolicyConfigStore(ABC):
    """Persistent storage for named policy configs."""

    @abstractmethod
    async def list_configs(self):
        # type: () -> List[Dict[str, Any]]
        raise NotImplementedError

    @abstractmethod
    async def write_configs(self, configs):
        # type: (List[Dict[str, Any]]) -> None
        raise NotImplementedError

    @abstractmethod
    async def healthcheck(self):
        # type: () -> Dict[str, Any]
        raise NotImplementedError


class ExternalAgentStore(ABC):
    """Persistent storage for external (cross-cloud / federated) agent metadata.

    Each entry is a dict with keys:
      name             — unique identifier matching the RBAC policy entry name
      invoke_url       — base URL for the agent (empty for SPIFFE-only callers)
      display_name     — human-friendly label
      transport        — "spiffe" | "https_only"
      hosting_platform — inferred from trust domain, e.g. "gcp", "external"
    """

    @abstractmethod
    async def list_agents(self):
        # type: () -> List[Dict[str, Any]]
        """Return all external agent entries."""
        raise NotImplementedError

    @abstractmethod
    async def put_agent(self, name, config):
        # type: (str, Dict[str, Any]) -> None
        """Upsert an agent entry.  ``name`` is the unique key."""
        raise NotImplementedError

    @abstractmethod
    async def delete_agent(self, name):
        # type: (str) -> None
        """Remove an agent entry by name.  No-op if not found."""
        raise NotImplementedError

    @abstractmethod
    async def healthcheck(self):
        # type: () -> Dict[str, Any]
        raise NotImplementedError
