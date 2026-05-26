"""API schemas."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FixType(str, Enum):
    MTLS_REMOVE = "mtls-remove"
    RBAC_POLICY = "rbac-policy"


class ExecuteRequest(BaseModel):
    caller: str = Field(min_length=1)
    method: HttpMethod = HttpMethod.GET
    path: str = Field(min_length=1)


class ExecuteA2ARequest(BaseModel):
    caller: str = Field(min_length=1)
    target: str = Field(min_length=1)


class MTLSPolicyUpdate(BaseModel):
    allowed_ids: List[str]


class PolicyConfigCreate(BaseModel):
    name: str = Field(min_length=1)
    yaml: str = Field(min_length=1)
    description: str = ""


class PolicyConfigEntry(BaseModel):
    name: str
    yaml: str
    description: str = ""
    created_at: str
    updated_at: str


class FixPayload(BaseModel):
    remove_id: Optional[str] = None
    yaml: Optional[str] = None


class QuickFixRequest(BaseModel):
    fix_type: FixType
    fix_payload: FixPayload = FixPayload()


class UpdateAgentRiskRequest(BaseModel):
    spiffe_id: str = Field(min_length=1)
    risk_level: RiskLevel


class ExternalAgentEntry(BaseModel):
    """Configuration record for a cross-cloud or federated external agent.

    Stored in the portal external-agent store and overlaid onto the admin-CP
    discovery results.  ``name`` must match the ``name`` field of the
    corresponding ``federated_policies`` entry in the RBAC YAML.
    """
    name: str = Field(min_length=1)
    invoke_url: str = ""
    display_name: str = ""
    transport: str = "spiffe"   # "spiffe" | "https_only"
    hosting_platform: str = ""  # e.g. "gcp", "external"
