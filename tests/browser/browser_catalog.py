"""Executable inventory; importing it never imports browser dependencies."""


def inventory():
    cases = []
    def add(suffix, profiles, description, expected, mutation=False):
        cases.append({
            "id": "browser." + suffix, "suite": "browser", "layer": "operator-browser",
            "profiles": profiles, "description": description, "expected": expected,
            "mutation": mutation,
        })
    for portal in ("management", "security"):
        add(f"{portal}.anonymous", ["local", "live"],
            f"{portal}: anonymous sign-in splash and protected API",
            "Authentication required; sign-in visible; protected read returns 401.")
        for role in ("admin", "viewer", "unassigned"):
            add(f"{portal}.{role}.access", ["local", "live"],
                f"{portal}: {role} session, UI role and server read authorization",
                "Unassigned sees denial and HTTP 403; assigned role matches and read returns 200; schema-invalid write probe returns 403 for viewer, 400/422 for admin.")
        for role in ("admin", "viewer"):
            add(f"{portal}.{role}.navigation", ["local", "live"],
                f"{portal}: {role} navigation and read-only forms",
                "Management seven tabs and agent details render; security inventory and confirmation cancel render.")
    add("management.local.execute-allow", ["local"],
        "Actual execute form, permitted read through fixture workload boundary",
        "POST /api/execute returns status 200 and UI renders 200 ALLOWED.")
    add("management.local.execute-deny", ["local"],
        "Actual execute form, explicit RBAC denial from fixture workload boundary",
        "POST /api/execute returns inner status 403 and UI renders 403 RBAC DENY.")
    add("management.local.saved-policy", ["local"],
        "Create and delete an isolated saved policy through the actual local store",
        "Scoped saved config round-trip succeeds and deletion is verified.", True)
    add("management.live.execute-read", ["live"],
        "Explicitly authorized test caller executes GET /budget/read from the UI",
        "Configured test caller returns inner HTTP 200 and UI renders ALLOWED.", True)
    return cases
