#!/bin/bash
# =============================================================================
# AIM Prototype Platform - SPIFFE Proxy Entrypoint (Join Token Attestation)
# =============================================================================
set -e

CONTAINER_MODE=${CONTAINER_MODE:-"agent-proxy"}

echo "============================================="
echo "  AIM Prototype Platform - SPIFFE Proxy Container"
echo "  Mode: ${CONTAINER_MODE}"
echo "  Attestation: Join Token"
echo "============================================="


if [ "$CONTAINER_MODE" = "server" ]; then
    echo "[Entrypoint] Starting SPIRE Server..."
    mkdir -p /opt/spire/data/server

    AZURE_TENANT_ID=${AZURE_TENANT_ID:-""}
    echo "[Entrypoint] Trust domain: aim.microsoft.com"

    # No tenant substitution needed for join_token, but keep config generic
    cp /opt/spire/conf/server.conf /opt/spire/conf/server-runtime.conf

    exec /opt/spire/bin/spire-server run -config /opt/spire/conf/server-runtime.conf

elif [ "$CONTAINER_MODE" = "agent-proxy" ]; then
    SPIRE_SERVER_ADDR=${SPIRE_SERVER_ADDR:-"spire-server"}
    JOIN_TOKEN=${JOIN_TOKEN:-""}

    echo "[Entrypoint] Configuring SPIRE Agent (join_token attestation)..."
    echo "[Entrypoint]   Server: ${SPIRE_SERVER_ADDR}:8081"
    mkdir -p /opt/spire/data/agent /opt/spire/sockets

    # Write the SPIRE trust bundle to disk for secure bootstrap (issue #63).
    # The bundle is extracted from the SPIRE server in deploy.sh Step 4.5
    # and passed as an env var to avoid insecure_bootstrap=true (MITM risk).
    SPIRE_TRUST_BUNDLE=${SPIRE_TRUST_BUNDLE:-""}
    if [ -z "$SPIRE_TRUST_BUNDLE" ]; then
        echo "[Entrypoint] ERROR: SPIRE_TRUST_BUNDLE env var not set."
        echo "[Entrypoint] The trust bundle is required for secure SPIRE agent bootstrap."
        echo "[Entrypoint] It should be extracted from the SPIRE server via:"
        echo "[Entrypoint]   docker exec spire-server spire-server bundle show -format pem"
        echo "[Entrypoint] See deploy.sh Step 4.5 and GitHub issue #63."
        exit 1
    fi
    echo "$SPIRE_TRUST_BUNDLE" > /opt/spire/conf/trust-bundle.pem
    echo "[Entrypoint]   Trust bundle written to /opt/spire/conf/trust-bundle.pem"

    sed "s/SPIRE_SERVER_ADDR_PLACEHOLDER/${SPIRE_SERVER_ADDR}/" \
        /opt/spire/conf/agent.conf > /opt/spire/conf/agent-runtime.conf

    if [ -z "$JOIN_TOKEN" ]; then
        echo "[Entrypoint] ERROR: JOIN_TOKEN must be set for agent-proxy mode"
        echo "[Entrypoint] Generate one on the server with:"
        echo "[Entrypoint]   spire-server token generate -spiffeID spiffe://aim.microsoft.com/agent/<name>"
        exit 1
    fi

    echo "[Entrypoint] Starting SPIRE Agent with join token..."
    echo "[Entrypoint]   Token: (present, not logged)"

    start_spire_agent() {
        /opt/spire/bin/spire-agent run \
            -config /opt/spire/conf/agent-runtime.conf \
            -joinToken "$JOIN_TOKEN" &
        SPIRE_PID=$!
        echo "[Entrypoint] SPIRE Agent started (PID: $SPIRE_PID)"
    }

    start_spire_agent

    echo "[Entrypoint] Waiting for SPIRE Agent Workload API socket..."
    for i in $(seq 1 90); do
        if [ -S /opt/spire/sockets/workload.sock ]; then
            echo "[Entrypoint] ✓ SPIRE Agent socket ready"
            break
        fi
        if ! kill -0 $SPIRE_PID 2>/dev/null; then
            echo "[Entrypoint] ERROR: SPIRE Agent process died during startup"
            cat /opt/spire/data/agent/agent.log 2>/dev/null || true
            exit 1
        fi
        sleep 1
    done

    if [ ! -S /opt/spire/sockets/workload.sock ]; then
        echo "[Entrypoint] ERROR: SPIRE Agent socket not ready after 90s"
        exit 1
    fi

    # Monitor SPIRE Agent in background — restart if it dies.
    # The agent holds the SVID credentials that the Go proxy needs for mTLS.
    # Without this, a crashed agent silently breaks all tunnels while the
    # container appears healthy to the platform.
    # Note: on full container restart, the join token is already consumed so
    # re-attestation will fail — that requires fresh tokens (azure_msi long-term fix).
    (
        while true; do
            sleep 10
            if ! kill -0 $SPIRE_PID 2>/dev/null; then
                echo "[Monitor] SPIRE Agent (PID: $SPIRE_PID) died — restarting..."
                rm -f /opt/spire/sockets/workload.sock
                start_spire_agent
                # Wait for socket to come back
                for j in $(seq 1 60); do
                    if [ -S /opt/spire/sockets/workload.sock ]; then
                        echo "[Monitor] ✓ SPIRE Agent recovered (PID: $SPIRE_PID)"
                        break
                    fi
                    if ! kill -0 $SPIRE_PID 2>/dev/null; then
                        echo "[Monitor] SPIRE Agent died again during restart"
                        break
                    fi
                    sleep 1
                done
            fi
        done
    ) &

    echo "[Entrypoint] Starting SPIFFE Proxy (${PROXY_MODE} mode)..."
    exec /app/spiffe-proxy

else
    echo "[Entrypoint] ERROR: Unknown CONTAINER_MODE: ${CONTAINER_MODE}"
    exit 1
fi
