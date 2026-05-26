# ADR-006: Budget Backend Scenario (Not Abstract A1/A2/A3/A4)

**Status:** Accepted
**Date:** February 26, 2026
**Deciders:** Project contributors

## Context

The PoC originally used abstract agent names: A1-caller, A2-resource, A3-blocked, A4-caller. These were technically clear but hard to explain to non-specialist audiences. The Budget Backend scenario uses concrete business roles.

## Decision

**Rename all agents to the Budget Backend scenario.** Map PoC agents to business-relevant names that make the authorization model legible.

| Old Name | New Name | SPIFFE Path | Business Role |
|---|---|---|---|
| A1-caller | BudgetReport | `ests/bp/<bp-oid>/aid/<report-oid>` | Finance agent that reads budget data |
| A2-resource | BudgetBackend | `ests/bp/<bp-oid>/aid/<backend-oid>` | Protected API that holds budget data |
| A3-blocked | EmployeeMenus | `ests/bp/<bp-oid>/aid/<menus-oid>` | Cafeteria agent — no budget access |
| A4-caller | BudgetApproval | `ests/bp/<bp-oid>/aid/<approval-oid>` | Manager agent that reads and submits |

## Rationale

- **Three distinct enforcement patterns in one demo.** Read-only, full-access, and no-access are immediately legible as business rules, not abstract security policies.
- **Realistic enterprise names for demos.** "BudgetReport can read but not submit" is easier to understand than "A1 can call A2 on GET but not POST."
- **Big/Small approval split is just another policy line.** Easy to extend the demo with additional budget threshold rules without changing the architecture.

## Consequences

- Every file in the repo was renamed (source dirs, Bicep params, deploy.sh, SPIFFE IDs, test suite, all docs)
- Endpoints changed: `/execute` → `/budget/submit`, `/status` → `/budget/read`, `/call-a2` → `/call-backend`
- Zero old A1/A2/A3/A4 references remain — verified with grep across all source and doc files
- Future agents can be added to the scenario (e.g., "BudgetAudit" for compliance review)
