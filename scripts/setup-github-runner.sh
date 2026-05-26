#!/bin/bash
# =============================================================================
# Identity Research for Agent Management Using SPIFFE — Setup GitHub Actions Self-Hosted Runner with SPIRE + spiffe-proxy
# =============================================================================
# Idempotent. Runs as root via `az vm run-command create`.
# Installs:
#   1. GitHub Actions runner (registered to org/repo)
#   2. SPIRE agent (joins the Azure SPIRE server in the shared VNet)
#   3. spiffe-proxy (egress mode) — mTLS to budget-backend
#
# Required parameters (passed by deploy.sh GH5):
#   SPIRE_SERVER_IP            — Private IP of the Azure SPIRE server (e.g. 10.200.0.4)
#   SPIRE_TRUST_BUNDLE         — PEM of Azure SPIRE CA (base64-encoded — azure run-command
#                                args can't carry multi-line values safely)
#   SPIRE_JOIN_TOKEN           — Fresh join token for the runner
#   GITHUB_RUNNER_TOKEN        — Runner registration token
#   GITHUB_ORG / GITHUB_REPO   — GitHub destination
#   AGENT_NAME                 — Default: github-budget-reader
#   SPIRE_TRUST_DOMAIN         — Default: aim.microsoft.com
#   BLUEPRINT_APP_ID           — Blueprint app client ID (JWT audience)
#   AGENT_IDENTITY_ID          — Entra Agent Identity OID (ENTRA_AGENT_ID)
#   AZURE_TENANT_ID
#   ACR_LOGIN_SERVER           — ACR server for spiffe-proxy image
#   SPIFFE_PROXY_IMAGE         — e.g. spiffe-proxy:latest
#   BUDGET_BACKEND_FQDN        — e.g. budget-backend.internal.<...>.azurecontainerapps.io
#   BUDGET_BACKEND_SPIFFE_ID   — Peer SPIFFE ID allow list for egress proxy
# =============================================================================
set -euo pipefail

AGENT_NAME="${AGENT_NAME:-github-budget-reader}"
SPIRE_TRUST_DOMAIN="${SPIRE_TRUST_DOMAIN:-aim.microsoft.com}"
RUNNER_USER="azureuser"
RUNNER_DIR="/home/${RUNNER_USER}/actions-runner"
SPIRE_DIR="/opt/spire"
PROXY_PORT=8080

echo ""
echo "============================================================"
echo "  Identity Research for Agent Management Using SPIFFE — GitHub Runner Setup: ${AGENT_NAME}"
echo "============================================================"

# Required-param sanity checks (warn, don't abort — lets partial re-runs make progress)
for v in SPIRE_SERVER_IP SPIRE_TRUST_BUNDLE SPIRE_JOIN_TOKEN BUDGET_BACKEND_FQDN BUDGET_BACKEND_SPIFFE_ID; do
    if [[ -z "${!v:-}" ]]; then
        echo "WARNING: $v not set — downstream step may fail." >&2
    fi
done

# ─── Step 1: Install GitHub Actions Runner ────────────────────────────────

echo ""
echo "📦 Step 1/6 — Installing GitHub Actions runner..."

RUNNER_VERSION="2.321.0"
RUNNER_ARCHIVE="actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
RUNNER_URL="https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/${RUNNER_ARCHIVE}"

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

if [[ ! -f "./config.sh" ]]; then
    curl -sL "$RUNNER_URL" -o "$RUNNER_ARCHIVE"
    tar xzf "$RUNNER_ARCHIVE"
    rm -f "$RUNNER_ARCHIVE"
    echo "  ✅ Runner ${RUNNER_VERSION} extracted"
else
    echo "  ✅ Runner already installed — skipping download"
fi

if [[ ! -f ".runner" ]]; then
    if [[ -z "${GITHUB_RUNNER_TOKEN:-}" ]]; then
        echo "ERROR: GITHUB_RUNNER_TOKEN not set. Cannot register runner." >&2
        exit 1
    fi
    chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"
    su - "$RUNNER_USER" -c "cd $RUNNER_DIR && ./config.sh \
        --url \"https://github.com/${GITHUB_ORG}/${GITHUB_REPO}\" \
        --token \"$GITHUB_RUNNER_TOKEN\" \
        --name \"identity-spiffe-runner-\$(hostname)\" \
        --labels \"self-hosted,identity-spiffe-runner,Linux,X64\" \
        --runnergroup \"Default\" \
        --work \"_work\" \
        --unattended \
        --replace"
    echo "  ✅ Runner registered with GitHub"
else
    echo "  ✅ Runner already registered — skipping config"
fi

if ! systemctl is-active "actions.runner.*" >/dev/null 2>&1; then
    cd "$RUNNER_DIR"
    ./svc.sh install "$RUNNER_USER"
    ./svc.sh start
    echo "  ✅ Runner service installed and started"
else
    echo "  ✅ Runner service already running"
fi

chown -R "$RUNNER_USER:$RUNNER_USER" "$RUNNER_DIR"

# ─── Step 2: Install SPIRE Agent binary ───────────────────────────────────

echo ""
echo "🔐 Step 2/6 — Installing SPIRE agent..."

SPIRE_VERSION="1.10.4"
SPIRE_ARCHIVE="spire-${SPIRE_VERSION}-linux-amd64-musl.tar.gz"
SPIRE_URL="https://github.com/spiffe/spire/releases/download/v${SPIRE_VERSION}/${SPIRE_ARCHIVE}"

mkdir -p "${SPIRE_DIR}/bin" "${SPIRE_DIR}/data/agent" "${SPIRE_DIR}/conf" "${SPIRE_DIR}/sockets"

if [[ ! -f "${SPIRE_DIR}/bin/spire-agent" ]]; then
    cd /tmp
    curl -sL "$SPIRE_URL" -o "$SPIRE_ARCHIVE"
    tar xzf "$SPIRE_ARCHIVE"
    cp "spire-${SPIRE_VERSION}/bin/spire-agent" "${SPIRE_DIR}/bin/"
    rm -rf "spire-${SPIRE_VERSION}" "$SPIRE_ARCHIVE"
    chmod +x "${SPIRE_DIR}/bin/spire-agent"
    echo "  ✅ SPIRE agent ${SPIRE_VERSION} installed"
else
    echo "  ✅ SPIRE agent already installed — skipping"
fi

# Write trust bundle (Azure SPIRE CA PEM)
if [[ -n "${SPIRE_TRUST_BUNDLE:-}" ]]; then
    # Accept either raw PEM or base64-encoded PEM
    if [[ "$SPIRE_TRUST_BUNDLE" == *"BEGIN CERTIFICATE"* ]]; then
        echo "$SPIRE_TRUST_BUNDLE" > "${SPIRE_DIR}/conf/trust-bundle.pem"
    else
        echo "$SPIRE_TRUST_BUNDLE" | base64 -d > "${SPIRE_DIR}/conf/trust-bundle.pem"
    fi
    chmod 644 "${SPIRE_DIR}/conf/trust-bundle.pem"
    echo "  ✅ Trust bundle written to ${SPIRE_DIR}/conf/trust-bundle.pem"
else
    echo "  ⚠️  SPIRE_TRUST_BUNDLE not provided — agent will fail to start"
fi

# Write SPIRE agent config (includes trust_bundle_path — NOT insecure_bootstrap)
cat > "${SPIRE_DIR}/conf/agent.conf" << AGENTCONF
agent {
    data_dir = "${SPIRE_DIR}/data/agent"
    log_level = "INFO"
    server_address = "${SPIRE_SERVER_IP}"
    server_port = "8081"
    socket_path = "${SPIRE_DIR}/sockets/workload.sock"
    trust_domain = "${SPIRE_TRUST_DOMAIN}"
    trust_bundle_path = "${SPIRE_DIR}/conf/trust-bundle.pem"
}

plugins {
    NodeAttestor "join_token" {
        plugin_data {}
    }
    KeyManager "disk" {
        plugin_data {
            directory = "${SPIRE_DIR}/data/agent"
        }
    }
    WorkloadAttestor "unix" {
        plugin_data {
            discover_workload_path = true
        }
    }
}
AGENTCONF
echo "  ✅ SPIRE agent config written"

# ─── Step 3: Start SPIRE Agent with join token ────────────────────────────

echo ""
echo "🎟️  Step 3/6 — Configuring SPIRE agent systemd service..."

if [[ -z "${SPIRE_JOIN_TOKEN:-}" ]]; then
    echo "  ⚠️  SPIRE_JOIN_TOKEN not set — agent service written but not started"
else
    # Clean stale data dir from previous attestations (new token = new node identity)
    rm -rf "${SPIRE_DIR}/data/agent/bundle.der" \
           "${SPIRE_DIR}/data/agent/agent_svid.der" \
           "${SPIRE_DIR}/data/agent/svid.der" 2>/dev/null || true

    cat > /etc/systemd/system/spire-agent.service << SVCFILE
[Unit]
Description=SPIRE Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${SPIRE_DIR}/bin/spire-agent run -config ${SPIRE_DIR}/conf/agent.conf -joinToken ${SPIRE_JOIN_TOKEN}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCFILE

    systemctl daemon-reload
    systemctl enable spire-agent
    systemctl restart spire-agent
    echo "  ✅ SPIRE agent started with join token"

    # Wait for workload socket
    for i in $(seq 1 30); do
        if [[ -S "${SPIRE_DIR}/sockets/workload.sock" ]]; then
            echo "  ✅ SPIRE agent workload socket ready"
            break
        fi
        sleep 1
    done
fi

# ─── Step 4: Install spiffe-proxy from ACR ────────────────────────────────

echo ""
echo "🔄 Step 4/6 — Installing spiffe-proxy binary..."

if [[ -n "${ACR_LOGIN_SERVER:-}" && -n "${SPIFFE_PROXY_IMAGE:-}" ]]; then
    # Always re-extract: image may have been updated (idempotent is fine — it's 20MB)
    MSI_TOKEN=$(curl -s -H "Metadata: true" \
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://${ACR_LOGIN_SERVER}" \
        | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)

    if [[ -n "$MSI_TOKEN" ]]; then
        docker login "${ACR_LOGIN_SERVER}" -u 00000000-0000-0000-0000-000000000000 -p "$MSI_TOKEN" 2>/dev/null
        docker pull "${ACR_LOGIN_SERVER}/${SPIFFE_PROXY_IMAGE}" >/dev/null 2>&1 || true
        CONTAINER_ID=$(docker create "${ACR_LOGIN_SERVER}/${SPIFFE_PROXY_IMAGE}" 2>/dev/null || true)
        if [[ -n "$CONTAINER_ID" ]]; then
            docker cp "${CONTAINER_ID}:/app/spiffe-proxy" "${SPIRE_DIR}/bin/spiffe-proxy" 2>/dev/null || true
            docker rm "$CONTAINER_ID" 2>/dev/null || true
        fi
    fi

    if [[ -f "${SPIRE_DIR}/bin/spiffe-proxy" ]]; then
        chmod +x "${SPIRE_DIR}/bin/spiffe-proxy"
        echo "  ✅ spiffe-proxy installed at ${SPIRE_DIR}/bin/spiffe-proxy"
    else
        echo "  ⚠️  spiffe-proxy extraction failed — service start will be skipped"
    fi
else
    echo "  ⚠️  ACR_LOGIN_SERVER or SPIFFE_PROXY_IMAGE not set — skipping proxy install"
fi

# ─── Step 5: Configure spiffe-proxy egress (env-var driven) ───────────────

echo ""
echo "⚙️  Step 5/6 — Configuring spiffe-proxy egress service..."

# Env-var-driven — the binary reads PROXY_MODE, HTTP_LISTEN_ADDR, REMOTE_PROXY_ADDR,
# ALLOWED_REMOTE_SPIFFE_ID, SPIRE_SOCKET_PATH. CLI flags are NOT supported (see
# src/spiffe-proxy/cmd/main.go:45-60). Any prior unit using `agent-proxy -workloadSocket`
# was silently falling back to stale defaults.
cat > /etc/systemd/system/aim-spiffe-proxy.service << PROXYFILE
[Unit]
Description=Identity Research for Agent Management Using SPIFFE spiffe-proxy (egress — to ${BUDGET_BACKEND_FQDN:-<unset>})
After=spire-agent.service
Wants=spire-agent.service

[Service]
Type=simple
Environment=PROXY_MODE=egress
Environment=HTTP_LISTEN_ADDR=127.0.0.1:${PROXY_PORT}
Environment=REMOTE_PROXY_ADDR=${BUDGET_BACKEND_FQDN:-budget-backend.invalid}:8443
Environment=ALLOWED_REMOTE_SPIFFE_ID=${BUDGET_BACKEND_SPIFFE_ID:-spiffe://invalid}
Environment=SPIRE_SOCKET_PATH=${SPIRE_DIR}/sockets/workload.sock
ExecStart=${SPIRE_DIR}/bin/spiffe-proxy
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
PROXYFILE

systemctl daemon-reload
systemctl enable aim-spiffe-proxy

if [[ -f "${SPIRE_DIR}/bin/spiffe-proxy" ]] && systemctl is-active spire-agent >/dev/null 2>&1; then
    systemctl restart aim-spiffe-proxy
    echo "  ✅ spiffe-proxy egress → ${BUDGET_BACKEND_FQDN:-<unset>}:8443 (listening on 127.0.0.1:${PROXY_PORT})"
else
    echo "  ⚠️  spiffe-proxy service configured but not started (prereqs not ready)"
fi

# ─── Step 6: Write environment file for GitHub Actions ───────────────────

echo ""
echo "📝 Step 6/6 — Writing environment config..."

cat > /etc/identity-spiffe-github-runner.env << ENVFILE
# Identity Research for Agent Management Using SPIFFE GitHub Runner environment — consumed by workflow steps via envfile
TOKEN_SOURCE=github_oidc
ENTRA_OAUTH2_AUDIENCE=${BLUEPRINT_APP_ID:-PLACEHOLDER}
ENTRA_AGENT_ID=${AGENT_IDENTITY_ID:-PLACEHOLDER}
AZURE_TENANT_ID=${AZURE_TENANT_ID:-PLACEHOLDER}
AGENT_NAME=${AGENT_NAME}
SPIFFE_PROXY_URL=http://127.0.0.1:${PROXY_PORT}
ENVFILE
chmod 644 /etc/identity-spiffe-github-runner.env

echo "  ✅ Environment config written to /etc/identity-spiffe-github-runner.env"

# ─── Summary ─────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  ✅  GitHub Runner Setup Complete"
echo "============================================================"
echo "  Runner dir:         ${RUNNER_DIR}"
echo "  SPIRE agent socket: ${SPIRE_DIR}/sockets/workload.sock"
echo "  Proxy listen:       127.0.0.1:${PROXY_PORT}"
echo "  Proxy → backend:    ${BUDGET_BACKEND_FQDN:-<unset>}:8443"
echo "  Entra Agent OID:    ${AGENT_IDENTITY_ID:-PLACEHOLDER}"
echo "  Env file:           /etc/identity-spiffe-github-runner.env"
echo ""
echo "  Check services:"
echo "    systemctl status spire-agent aim-spiffe-proxy actions.runner.*"
echo ""
