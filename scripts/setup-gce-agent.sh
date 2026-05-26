#!/usr/bin/env bash
# =============================================================================
# setup-gce-agent.sh — Master GCE VM Setup for Cross-Cloud Identity Research for Agent Management Using SPIFFE Agent
# =============================================================================
# Installs and configures SPIRE server + agent, demo-agent app, and
# spiffe-proxy (egress) with systemd units so everything survives reboots.
#
# Designed to run LOCALLY on the GCE VM. deploy.sh scp's this script
# to the VM and executes it via SSH.
#
# Idempotent — safe to re-run.
#
# Required env vars (or pass as args):
#   BLUEPRINT_APP_ID          — Entra Blueprint application (client) ID
#   GOOGLE_AGENT_ID           — Google Agent Identity application ID
#   AZURE_TENANT_ID           — Azure tenant ID
#   AZURE_SPIRE_SERVER_IP     — Private IP of the Azure SPIRE server
#   BUDGET_BACKEND_FQDN       — FQDN of budget-backend Container App
#   BUDGET_BACKEND_SPIFFE_ID  — SPIFFE ID of budget-backend
#   ACR_SERVER                — ACR server (e.g., crdtfodca2et7ey.azurecr.io)
#   ACR_TOKEN_USER            — ACR token username
#   ACR_TOKEN_PASS            — ACR token password
#
# Usage:
#   BLUEPRINT_APP_ID=... GOOGLE_AGENT_ID=... ... ./setup-gce-agent.sh
#   ./setup-gce-agent.sh --blueprint-app-id ... --google-agent-id ... ...
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Logging helpers (match repo convention from provision-gce-vm.sh)
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
step()  { echo -e "\n${CYAN}=== Step $1: $2 ===${NC}"; }

# ---------------------------------------------------------------------------
# Parse CLI args (override env vars if provided)
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --blueprint-app-id)       BLUEPRINT_APP_ID="$2";         shift 2 ;;
        --google-agent-id)        GOOGLE_AGENT_ID="$2";          shift 2 ;;
        --azure-tenant-id)        AZURE_TENANT_ID="$2";          shift 2 ;;
        --azure-spire-server-ip)  AZURE_SPIRE_SERVER_IP="$2";    shift 2 ;;
        --budget-backend-fqdn)    BUDGET_BACKEND_FQDN="$2";      shift 2 ;;
        --budget-backend-spiffe-id) BUDGET_BACKEND_SPIFFE_ID="$2"; shift 2 ;;
        --acr-server)             ACR_SERVER="$2";               shift 2 ;;
        --acr-token-user)         ACR_TOKEN_USER="$2";           shift 2 ;;
        --acr-token-pass)         ACR_TOKEN_PASS="$2";           shift 2 ;;
        *) error "Unknown arg: $1"; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Validate required env vars
# ---------------------------------------------------------------------------
MISSING=()
for VAR in BLUEPRINT_APP_ID GOOGLE_AGENT_ID AZURE_TENANT_ID AZURE_SPIRE_SERVER_IP \
           BUDGET_BACKEND_FQDN BUDGET_BACKEND_SPIFFE_ID ACR_SERVER ACR_TOKEN_USER ACR_TOKEN_PASS; do
    if [[ -z "${!VAR:-}" ]]; then
        MISSING+=("$VAR")
    fi
done
if [[ ${#MISSING[@]} -gt 0 ]]; then
    error "Missing required environment variables:"
    for v in "${MISSING[@]}"; do echo "  - $v"; done
    exit 1
fi

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SPIRE_VERSION="1.9.6"
SPIRE_DIR="/opt/spire"
AGENT_DIR="/opt/aim-agent"
TRUST_DOMAIN="gcp.aim.microsoft.com"
AZURE_TRUST_DOMAIN="aim.microsoft.com"
GOOGLE_SPIFFE="spiffe://${TRUST_DOMAIN}/ests/bp/${BLUEPRINT_APP_ID}/aid/${GOOGLE_AGENT_ID}"

# =====================================================================
# Step 1: Install SPIRE from tarball
# =====================================================================
step 1 "Install SPIRE ${SPIRE_VERSION}"

if [[ -f "${SPIRE_DIR}/bin/spire-server" ]]; then
    info "SPIRE already installed at ${SPIRE_DIR}/bin/spire-server — skipping"
    mkdir -p "${SPIRE_DIR}"/{conf,data/server,data/agent,sockets,bin}
else
    info "Downloading SPIRE ${SPIRE_VERSION}..."
    mkdir -p "${SPIRE_DIR}"/{conf,data/server,data/agent,sockets,bin}
    TARBALL="${SPIRE_DIR}/spire-${SPIRE_VERSION}.tar.gz"
    curl -sSfL -o "${TARBALL}" \
        "https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz"
    tar xzf "${TARBALL}" --strip-components=1 -C "${SPIRE_DIR}"
    rm -f "${TARBALL}"
    info "SPIRE installed to ${SPIRE_DIR}"
fi

# =====================================================================
# Step 2: Write SPIRE server config
# =====================================================================
step 2 "Write SPIRE server config"

cat > "${SPIRE_DIR}/conf/server.conf" << 'SERVEREOF'
server {
    bind_address = "0.0.0.0"
    bind_port = "8081"
    socket_path = "/opt/spire/data/server/api.sock"
    trust_domain = "gcp.aim.microsoft.com"
    data_dir = "/opt/spire/data/server"
    log_level = "DEBUG"

    ca_ttl = "168h"
    default_x509_svid_ttl = "12h"

    ca_subject {
        country = ["US"]
        organization = ["Microsoft"]
        common_name = "Identity Research for Agent Management Using SPIFFE GCP SPIRE CA"
    }

    federation {
        bundle_endpoint {
            address = "0.0.0.0"
            port = 8443
        }
    }
}

plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "/opt/spire/data/server/datastore.sqlite3"
        }
    }

    NodeAttestor "join_token" {
        plugin_data {}
    }

    KeyManager "disk" {
        plugin_data {
            keys_path = "/opt/spire/data/server/keys.json"
        }
    }
}
SERVEREOF
info "Wrote ${SPIRE_DIR}/conf/server.conf (trust_domain=${TRUST_DOMAIN})"

# =====================================================================
# Step 3: Write SPIRE agent config
# =====================================================================
step 3 "Write SPIRE agent config"

cat > "${SPIRE_DIR}/conf/agent.conf" << 'AGENTEOF'
agent {
    data_dir = "/opt/spire/data/agent"
    log_level = "DEBUG"
    trust_domain = "gcp.aim.microsoft.com"
    server_address = "127.0.0.1"
    server_port = "8081"
    socket_path = "/opt/spire/sockets/workload.sock"
    insecure_bootstrap = true
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }

    WorkloadAttestor "unix" {
        plugin_data {
            discover_workload_path = true
        }
    }

    KeyManager "disk" {
        plugin_data {
            directory = "/opt/spire/data/agent"
        }
    }
}
AGENTEOF
info "Wrote ${SPIRE_DIR}/conf/agent.conf (insecure_bootstrap for local server)"

# =====================================================================
# Step 4: Create systemd unit for SPIRE server
# =====================================================================
step 4 "Create systemd unit — gcp-spire-server"

cat > /etc/systemd/system/gcp-spire-server.service << 'EOF'
[Unit]
Description=GCP SPIRE Server (gcp.aim.microsoft.com)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/spire/bin/spire-server run -config /opt/spire/conf/server.conf
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
info "Wrote gcp-spire-server.service"

# =====================================================================
# Step 5: Create agent start wrapper + systemd unit for SPIRE agent
# =====================================================================
step 5 "Create SPIRE agent wrapper + systemd unit — gcp-spire-agent"

# The agent needs a fresh join token each time it starts. This wrapper
# generates one from the local SPIRE server and passes it to the agent.
cat > "${SPIRE_DIR}/bin/start-agent.sh" << 'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

TOKEN_FILE="/opt/spire/data/agent/join-token"
mkdir -p /opt/spire/data/agent

# Wait for the SPIRE server to be healthy
for i in $(seq 1 30); do
    if /opt/spire/bin/spire-server healthcheck -socketPath /opt/spire/data/server/api.sock 2>/dev/null; then
        break
    fi
    echo "[start-agent] Waiting for SPIRE server... ($i/30)"
    sleep 2
done

# Generate a fresh join token (1h TTL)
TOKEN=$(/opt/spire/bin/spire-server token generate -ttl 3600 \
    -socketPath /opt/spire/data/server/api.sock 2>/dev/null \
    | grep -i token | awk '{print $NF}')
if [[ -z "${TOKEN}" ]]; then
    echo "[start-agent] ERROR: Failed to generate join token"
    exit 1
fi
echo "${TOKEN}" > "${TOKEN_FILE}"
echo "[start-agent] Join token generated, starting agent..."

# Clean stale agent data so re-attestation works
rm -f /opt/spire/data/agent/agent_svid.der \
      /opt/spire/data/agent/bundle.der \
      /opt/spire/data/agent/keys.json

exec /opt/spire/bin/spire-agent run \
    -config /opt/spire/conf/agent.conf \
    -joinToken "${TOKEN}"
WRAPPER
chmod +x "${SPIRE_DIR}/bin/start-agent.sh"

cat > /etc/systemd/system/gcp-spire-agent.service << 'EOF'
[Unit]
Description=GCP SPIRE Agent (gcp.aim.microsoft.com)
After=gcp-spire-server.service
Requires=gcp-spire-server.service

[Service]
Type=simple
ExecStart=/opt/spire/bin/start-agent.sh
Restart=always
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
info "Wrote gcp-spire-agent.service + start-agent.sh wrapper"

# =====================================================================
# Step 6: Start SPIRE server + agent
# =====================================================================
step 6 "Start SPIRE services"

systemctl daemon-reload
systemctl enable --now gcp-spire-server

# Wait for server to become healthy
info "Waiting for SPIRE server to become healthy..."
for i in $(seq 1 30); do
    if "${SPIRE_DIR}/bin/spire-server" healthcheck \
        -socketPath "${SPIRE_DIR}/data/server/api.sock" 2>/dev/null; then
        info "SPIRE server is healthy"
        break
    fi
    if [[ "$i" -eq 30 ]]; then
        error "SPIRE server failed to start within 60s"
        journalctl -u gcp-spire-server --no-pager -n 20
        exit 1
    fi
    sleep 2
done

systemctl enable --now gcp-spire-agent

# Wait for agent to attest
info "Waiting for SPIRE agent to attest..."
for i in $(seq 1 30); do
    if "${SPIRE_DIR}/bin/spire-agent" healthcheck \
        -socketPath "${SPIRE_DIR}/sockets/workload.sock" 2>/dev/null; then
        info "SPIRE agent is healthy"
        break
    fi
    if [[ "$i" -eq 30 ]]; then
        error "SPIRE agent failed to start within 60s"
        journalctl -u gcp-spire-agent --no-pager -n 20
        exit 1
    fi
    sleep 2
done

# =====================================================================
# Step 7: Configure SPIRE federation with Azure trust domain
# Bundle exchange MUST happen before workload entry creation because
# -federatesWith requires the target trust domain bundle to exist.
# =====================================================================
step 7 "Configure SPIRE federation bundle (${AZURE_TRUST_DOMAIN})"

BUNDLE_EXISTS=$("${SPIRE_DIR}/bin/spire-server" bundle list \
    -socketPath "${SPIRE_DIR}/data/server/api.sock" 2>/dev/null \
    | grep "${AZURE_TRUST_DOMAIN}" || true)

if [[ -n "${BUNDLE_EXISTS}" ]]; then
    info "Federation bundle for ${AZURE_TRUST_DOMAIN} already configured — skipping"
else
    info "Fetching trust bundle from Azure SPIRE server at ${AZURE_SPIRE_SERVER_IP}:8443..."
    # Attempt to fetch and set the Azure bundle; warn but don't fail if
    # VPN/connectivity isn't ready yet (Phase 0 may not be deployed).
    if "${SPIRE_DIR}/bin/spire-server" bundle set \
        -socketPath "${SPIRE_DIR}/data/server/api.sock" \
        -id "spiffe://${AZURE_TRUST_DOMAIN}" \
        -format spiffe \
        -path <(curl -sSf --connect-timeout 10 \
            "https://${AZURE_SPIRE_SERVER_IP}:8443" \
            --insecure 2>/dev/null) 2>/dev/null; then
        info "Azure federation bundle configured"
    else
        warn "Could not fetch Azure trust bundle — federation will fail until"
        warn "VPN is up and bundle is manually imported. Continuing setup..."
    fi
fi

# =====================================================================
# Step 8: Register workload entry (after bundle exchange)
# =====================================================================
step 8 "Register workload entry"

EXISTING_ENTRIES=$("${SPIRE_DIR}/bin/spire-server" entry show \
    -socketPath "${SPIRE_DIR}/data/server/api.sock" \
    -spiffeID "${GOOGLE_SPIFFE}" 2>/dev/null || true)

if echo "${EXISTING_ENTRIES}" | grep -q "${GOOGLE_SPIFFE}"; then
    info "Workload entry already exists for ${GOOGLE_SPIFFE} — skipping"
else
    # Get the parent (agent) SPIFFE ID
    PARENT_ID=$("${SPIRE_DIR}/bin/spire-server" agent list \
        -socketPath "${SPIRE_DIR}/data/server/api.sock" 2>/dev/null \
        | grep 'SPIFFE ID' | head -1 | awk '{print $NF}')
    if [[ -z "${PARENT_ID}" ]]; then
        error "No SPIRE agent found — cannot register workload entry"
        exit 1
    fi
    info "Registering workload entry:"
    info "  SPIFFE ID:     ${GOOGLE_SPIFFE}"
    info "  Parent:        ${PARENT_ID}"
    info "  FederatesWith: ${AZURE_TRUST_DOMAIN}"

    "${SPIRE_DIR}/bin/spire-server" entry create \
        -socketPath "${SPIRE_DIR}/data/server/api.sock" \
        -parentID "${PARENT_ID}" \
        -spiffeID "${GOOGLE_SPIFFE}" \
        -selector unix:uid:0 \
        -federatesWith "${AZURE_TRUST_DOMAIN}"
    info "Workload entry registered"
fi

# =====================================================================
# Step 8: Extract spiffe-proxy binary from ACR Docker image
# =====================================================================
step 9 "Extract spiffe-proxy binary from Docker image"

if [[ -f "${SPIRE_DIR}/bin/spiffe-proxy" ]]; then
    info "spiffe-proxy already installed at ${SPIRE_DIR}/bin/spiffe-proxy — skipping"
else
    info "Logging into ACR (${ACR_SERVER})..."
    docker login "${ACR_SERVER}" -u "${ACR_TOKEN_USER}" -p "${ACR_TOKEN_PASS}"

    IMAGE_TAG="${IMAGE_TAG:-v22}"
    PROXY_IMAGE="${ACR_SERVER}/spiffe-proxy:${IMAGE_TAG}"
    info "Pulling ${PROXY_IMAGE}..."
    docker pull "${PROXY_IMAGE}"

    # Extract binary from the image
    CONTAINER_NAME="proxy-extract-$$"
    docker create --name "${CONTAINER_NAME}" "${PROXY_IMAGE}" >/dev/null
    docker cp "${CONTAINER_NAME}:/app/spiffe-proxy" "${SPIRE_DIR}/bin/spiffe-proxy"
    docker rm "${CONTAINER_NAME}" >/dev/null
    chmod +x "${SPIRE_DIR}/bin/spiffe-proxy"
    info "spiffe-proxy extracted to ${SPIRE_DIR}/bin/spiffe-proxy"
fi

# =====================================================================
# Step 9: Install Python dependencies for demo-agent
# =====================================================================
step 10 "Install Python dependencies"

if python3 -c "import fastapi, uvicorn, httpx" 2>/dev/null; then
    info "Python dependencies already installed — skipping"
else
    info "Installing fastapi, uvicorn, httpx..."
    if command -v pip3 &>/dev/null; then
        pip3 install --quiet fastapi uvicorn httpx
    else
        apt-get update -qq && apt-get install -y -qq python3-pip
        pip3 install --quiet fastapi uvicorn httpx
    fi
    info "Python dependencies installed"
fi

# =====================================================================
# Step 10: Write agent environment file
# =====================================================================
step 11 "Write agent environment file"

mkdir -p "${AGENT_DIR}"

cat > "${AGENT_DIR}/env" << EOF
AGENT_NAME=google-budget-reader
TOKEN_SOURCE=google_oidc
ENTRA_OAUTH2_AUDIENCE=${BLUEPRINT_APP_ID}
ENTRA_AGENT_ID=${GOOGLE_AGENT_ID}
AZURE_TENANT_ID=${AZURE_TENANT_ID}
BACKEND_ENDPOINT=http://localhost:8080
SPIRE_SOCKET_PATH=${SPIRE_DIR}/sockets/workload.sock
MGMT_API_KEY=${MGMT_API_KEY:-}
EOF
info "Wrote ${AGENT_DIR}/env"

# =====================================================================
# Step 11: Add /cloud-identity endpoint to demo-agent app
# =====================================================================
step 12 "Add /cloud-identity endpoint to demo-agent app"

if [[ ! -f "${AGENT_DIR}/app.py" ]]; then
    warn "${AGENT_DIR}/app.py not found — skipping /cloud-identity injection."
    warn "Ensure app files are scp'd to ${AGENT_DIR}/ before running this script."
else
    if grep -q "cloud-identity" "${AGENT_DIR}/app.py"; then
        info "/cloud-identity endpoint already present — skipping"
    else
        info "Appending /cloud-identity endpoint to app.py..."
        cat >> "${AGENT_DIR}/app.py" << 'CLOUDID'


# ---------------------------------------------------------------------------
# /cloud-identity — GCE metadata provenance proof (added by setup-gce-agent.sh)
# ---------------------------------------------------------------------------
@app.get("/cloud-identity")
async def cloud_identity():
    """Return GCE instance metadata to prove this agent runs on Google Cloud."""
    import httpx as _httpx
    meta = {}
    base = "http://metadata.google.internal/computeMetadata/v1"
    headers = {"Metadata-Flavor": "Google"}
    try:
        async with _httpx.AsyncClient(timeout=5) as c:
            for key, path in [
                ("project_id", "/project/project-id"),
                ("zone", "/instance/zone"),
                ("instance_name", "/instance/name"),
                ("instance_id", "/instance/id"),
                ("service_account", "/instance/service-accounts/default/email"),
            ]:
                resp = await c.get(f"{base}{path}", headers=headers)
                meta[key] = resp.text if resp.status_code == 200 else None
    except Exception as e:
        meta["error"] = str(e)
    return {"cloud_provider": "gcp", "metadata": meta}
CLOUDID
        info "/cloud-identity endpoint appended"
    fi
fi

# =====================================================================
# Step 11b: Add /call-backend-raw endpoint (portal proxy support)
# =====================================================================
step 12 "Add /call-backend-raw endpoint to demo-agent app"

if [[ -f "${AGENT_DIR}/app.py" ]]; then
    if grep -q "call-backend-raw" "${AGENT_DIR}/app.py"; then
        info "/call-backend-raw endpoint already present — skipping"
    else
        info "Appending /call-backend-raw + /flush-token endpoints to app.py..."
        cat >> "${AGENT_DIR}/app.py" << 'CALLRAW'


# ---------------------------------------------------------------------------
# /call-backend-raw — Portal proxy endpoint (added by setup-gce-agent.sh)
# ---------------------------------------------------------------------------
import secrets as _secrets
import re as _re
from starlette.requests import Request as _Request
from starlette.responses import JSONResponse as _JSONResponse

_ADMIN_KEY = os.getenv("MGMT_API_KEY", "")
_ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH"}
_ALLOWED_PATH_RE = _re.compile(r"^/[a-zA-Z0-9_./-]{1,200}$")

@app.post("/call-backend-raw")
async def call_backend_raw(request: _Request, method: str = "GET", path: str = "/budget/read", body: str = ""):
    """Portal-compatible proxy: call BudgetBackend via SPIFFE egress sidecar."""
    if not _ADMIN_KEY:
        return _JSONResponse({"error": "management API key not configured"}, status_code=500)
    if not _secrets.compare_digest(request.headers.get("X-Spiffe-Admin-Key", ""), _ADMIN_KEY):
        return _JSONResponse(
            {"caller": AGENT_NAME, "http_status": 401, "error": "unauthorized"},
            status_code=401,
        )

    if method.upper() not in _ALLOWED_METHODS:
        return {"caller": AGENT_NAME, "error": f"Method not allowed: {method}", "http_status": 400}
    if not _ALLOWED_PATH_RE.match(path):
        return {"caller": AGENT_NAME, "error": f"Path not allowed: {path}", "http_status": 400}

    url = f"{BACKEND_ENDPOINT}{path}"
    headers = {"X-Caller-Agent": AGENT_NAME, "Content-Type": "application/json"}

    try:
        token = get_entra_token()
        headers["Authorization"] = f"Bearer {token}"
    except Exception as e:
        return {
            "caller": AGENT_NAME, "target": "budget-backend",
            "method": method.upper(), "path": path,
            "http_status": 401,
            "response": {"error": "token_acquisition_failed", "detail": str(e)},
        }

    request_body = body if body else None
    if not request_body and method.upper() in ("POST", "PUT", "PATCH"):
        request_body = '{"amount": 5000, "description": "Cross-cloud test from google-budget-reader"}'

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.request(
                method=method.upper(), url=url, headers=headers, content=request_body,
            )
        try:
            resp_body = response.json()
        except Exception:
            resp_body = response.text
        return {
            "caller": AGENT_NAME, "target": "budget-backend",
            "method": method.upper(), "path": path,
            "http_status": response.status_code, "response": resp_body,
        }
    except Exception as e:
        return {
            "caller": AGENT_NAME, "target": "budget-backend",
            "method": method.upper(), "path": path,
            "http_status": 0, "error": str(e),
        }


@app.post("/flush-token")
async def flush_token():
    """Clear cached Entra token so next request acquires a fresh one."""
    from entra_token_exchange import _token_cache
    _token_cache.clear()
    return {"status": "flushed", "agent": AGENT_NAME}
CALLRAW
        info "/call-backend-raw + /flush-token endpoints appended"
    fi
fi

# =====================================================================
# Step 12: Create systemd unit for demo-agent
# =====================================================================
step 13 "Create systemd unit — aim-agent"

cat > /etc/systemd/system/aim-agent.service << EOF
[Unit]
Description=Identity Research for Agent Management Using SPIFFE Google Budget Reader Agent (FastAPI)
After=network-online.target gcp-spire-agent.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${AGENT_DIR}/env
WorkingDirectory=${AGENT_DIR}
ExecStart=/usr/bin/python3 -m uvicorn app:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
info "Wrote aim-agent.service"

# =====================================================================
# Step 13: Create systemd unit for spiffe-proxy (egress)
# =====================================================================
step 14 "Create systemd unit — aim-spiffe-proxy"

cat > /etc/systemd/system/aim-spiffe-proxy.service << EOF
[Unit]
Description=SPIFFE Proxy (Egress) for Google Budget Reader
After=gcp-spire-agent.service
Wants=gcp-spire-agent.service

[Service]
Type=simple
Environment=PROXY_MODE=egress
Environment=HTTP_LISTEN_ADDR=:8080
Environment=REMOTE_PROXY_ADDR=${BUDGET_BACKEND_FQDN}:8443
Environment=ALLOWED_REMOTE_SPIFFE_ID=${BUDGET_BACKEND_SPIFFE_ID}
Environment=SPIRE_SOCKET_PATH=${SPIRE_DIR}/sockets/workload.sock
ExecStart=${SPIRE_DIR}/bin/spiffe-proxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
info "Wrote aim-spiffe-proxy.service"

# =====================================================================
# Step 14: Enable and start all services
# =====================================================================
step 15 "Enable and start all services"

systemctl daemon-reload

# Restart services that were already running (config may have changed)
for SVC in gcp-spire-server gcp-spire-agent aim-agent aim-spiffe-proxy; do
    if systemctl is-active --quiet "${SVC}" 2>/dev/null; then
        info "Restarting ${SVC} (already running, config may have changed)..."
        systemctl restart "${SVC}"
    else
        info "Starting ${SVC}..."
        systemctl enable --now "${SVC}"
    fi
done

# =====================================================================
# Step 15: Health checks
# =====================================================================
step 16 "Health checks"

PASS=0
FAIL=0

check() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        info "✓ ${name}"
        PASS=$((PASS + 1))
    else
        warn "✗ ${name}"
        FAIL=$((FAIL + 1))
    fi
}

sleep 3  # give services a moment

check "SPIRE server" "${SPIRE_DIR}/bin/spire-server" healthcheck \
    -socketPath "${SPIRE_DIR}/data/server/api.sock"

check "SPIRE agent" "${SPIRE_DIR}/bin/spire-agent" healthcheck \
    -socketPath "${SPIRE_DIR}/sockets/workload.sock"

check "Demo agent (port 8000)" curl -sf http://localhost:8000/health

check "spiffe-proxy (systemd active)" systemctl is-active --quiet aim-spiffe-proxy

echo ""
info "Health checks: ${PASS} passed, ${FAIL} failed"

if [[ ${FAIL} -gt 0 ]]; then
    warn "Some services are not healthy. Check logs with:"
    echo "  journalctl -u gcp-spire-server --no-pager -n 20"
    echo "  journalctl -u gcp-spire-agent  --no-pager -n 20"
    echo "  journalctl -u aim-agent        --no-pager -n 20"
    echo "  journalctl -u aim-spiffe-proxy --no-pager -n 20"
fi

# =====================================================================
# Summary
# =====================================================================
echo ""
info "============================================"
info " GCE Agent Setup Complete"
info "============================================"
info "Trust domain:    ${TRUST_DOMAIN}"
info "SPIFFE ID:       ${GOOGLE_SPIFFE}"
info "Agent app:       http://localhost:8000"
info "Egress proxy:    localhost:8080 → ${BUDGET_BACKEND_FQDN}:8443"
info ""
info "systemd services:"
info "  gcp-spire-server   — SPIRE server"
info "  gcp-spire-agent    — SPIRE agent (auto-generates join token)"
info "  aim-agent          — FastAPI demo agent"
info "  aim-spiffe-proxy   — SPIFFE egress proxy"
info ""
info "All services are enabled and will start on reboot."
