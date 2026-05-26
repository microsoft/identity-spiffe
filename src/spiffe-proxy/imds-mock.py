#!/usr/bin/env python3
"""
IMDS Shim for SPIRE azure_msi Plugin
=====================================
PoC ONLY — NOT FOR PRODUCTION.

Translates SPIRE's IMDS calls into Container Apps' local MSI endpoint.

Container Apps uses:
  - IDENTITY_ENDPOINT=http://localhost:12356/msi/token
  - IDENTITY_HEADER=<secret>

SPIRE's azure_msi agent plugin calls:
  GET http://169.254.169.254/metadata/identity/oauth2/token
    ?api-version=2018-02-01
    &resource=https://management.azure.com/

This shim proxies to:
  GET http://localhost:12356/msi/token
    ?api-version=2019-08-01
    &resource=https://management.azure.com/
    &client_id=<MI_CLIENT_ID>           ← INJECTED if not in original request
  Headers: X-IDENTITY-HEADER: <secret>

The client_id is required when a Container App has multiple user-assigned
managed identities (which ours do — each app has its own).
"""
import json
import http.server
import os
import sys
import urllib.request
import urllib.parse
import urllib.error

# Container Apps MSI endpoint (injected by platform)
IDENTITY_ENDPOINT = os.environ.get("IDENTITY_ENDPOINT", "http://localhost:12356/msi/token")
IDENTITY_HEADER = os.environ.get("IDENTITY_HEADER", os.environ.get("MSI_SECRET", ""))

# Client ID of the user-assigned managed identity for THIS container app.
# Required when multiple MIs exist. Set via AZURE_CLIENT_ID env var.
MI_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")


class IMDSShimHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Metadata", "").lower() != "true":
            self.send_error(400, "Missing Metadata:true header")
            return

        if "/metadata/identity/oauth2/token" in self.path:
            self._proxy_token_request()
        elif "/metadata/instance" in self.path:
            self._return_instance_metadata()
        else:
            self.send_error(404, "Not found (IMDS shim)")

    def _proxy_token_request(self):
        """Proxy IMDS token request → Container Apps MSI endpoint."""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        resource = params.get("resource", ["https://management.azure.com/"])[0]
        client_id = params.get("client_id", [None])[0]

        # Build Container Apps token request
        ca_params = {
            "api-version": "2019-08-01",
            "resource": resource,
        }

        # Inject client_id if not provided by caller AND we have one configured
        if client_id:
            ca_params["client_id"] = client_id
        elif MI_CLIENT_ID:
            ca_params["client_id"] = MI_CLIENT_ID

        ca_url = f"{IDENTITY_ENDPOINT}?{urllib.parse.urlencode(ca_params)}"

        req = urllib.request.Request(ca_url)
        req.add_header("X-IDENTITY-HEADER", IDENTITY_HEADER)

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                cid_msg = f", client_id={MI_CLIENT_ID[:8]}..." if MI_CLIENT_ID else ""
                print(f"[IMDS-Shim] Token proxied OK (resource={resource}{cid_msg})", flush=True)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            print(f"[IMDS-Shim] Token proxy error: {e.code} {error_body}", flush=True)
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(error_body.encode())
        except Exception as e:
            print(f"[IMDS-Shim] Token proxy exception: {e}", flush=True)
            self.send_error(502, f"Failed to reach Container Apps MSI endpoint: {e}")

    def _return_instance_metadata(self):
        """Return instance metadata.
        
        On the SPIRE Server, the azure_msi plugin calls this during Configure()
        to discover subscription/resource group for ARM queries. We return
        real metadata from the VM's IMDS if available, or synthetic data.
        """
        # Try to get real instance metadata from actual IMDS (works on VMs)
        # This is needed because the server plugin wants subscriptionId etc.
        try:
            real_imds = urllib.request.Request(
                "http://169.254.169.254/metadata/instance?api-version=2017-08-01&format=json"
            )
            real_imds.add_header("Metadata", "true")
            with urllib.request.urlopen(real_imds, timeout=2) as r:
                body = r.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)
                print("[IMDS-Shim] Instance metadata proxied from real IMDS", flush=True)
                return
        except Exception:
            pass  # Not on a VM or IMDS unreachable, use synthetic

        resp = {
            "compute": {
                "azEnvironment": "AzurePublicCloud",
                "location": "northcentralus",
                "name": "spire-agent-shim",
                "vmId": "00000000-0000-0000-0000-000000000000",
                "subscriptionId": "00000000-0000-0000-0000-000000000000",
                "resourceGroupName": "unknown",
            },
            "network": {"interface": []},
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, format, *args):
        print(f"[IMDS-Shim] {args[0]}", flush=True)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 80
    bind = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"

    print(f"[IMDS-Shim] Listening on {bind}:{port}", flush=True)
    print(f"[IMDS-Shim] IDENTITY_ENDPOINT={IDENTITY_ENDPOINT}", flush=True)
    print(f"[IMDS-Shim] IDENTITY_HEADER={'*' * len(IDENTITY_HEADER)} ({len(IDENTITY_HEADER)} chars)", flush=True)
    print(f"[IMDS-Shim] MI_CLIENT_ID={MI_CLIENT_ID or '(not set — will fail if multiple MIs)'}", flush=True)
    print("[IMDS-Shim] PoC ONLY — proxying IMDS token requests to Container Apps MSI endpoint", flush=True)

    server = http.server.HTTPServer((bind, port), IMDSShimHandler)
    server.serve_forever()
