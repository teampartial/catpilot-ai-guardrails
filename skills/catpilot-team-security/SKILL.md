---
name: catpilot-team-security
description: "Use when: applying private Catpilot team security memory generated from approved security events and guardrail reviews."
version: 0.1.0
tags:
  - security
  - catpilot
  - team-memory
---

# Catpilot Team Security Memory

This is the private team overlay for Catpilot security memory. It intentionally does not contain the public `catpilot-security-core` rules.

Install and use `catpilot-security-core` as the universal security baseline. Use this private skill only for patterns this team has actually seen, reviewed, and approved.

Keep source incidents, customer data, employee identifiers, secrets, and internal ticket details out of this file.

## Operating Rule

When a task matches a team memory rule below, follow the approved remediation pattern. If a proposed change conflicts with a team rule, explain the conflict and ask before continuing.

## Team Memory Rules

No approved team-specific rules yet. Approved Memory Inbox items will be appended below.

<!-- catpilot-team-memory-rules team_id=5 -->
### Live test: approve a synthetic Memory Inbox item into the private team overlay for teampartial.

- Rule ID: `appsec-1778679976`
- Source: `appsec` / `appsec`
- Source Event: `1778679976`
- Approved By: `basil@catpilot.ai`
- Generated: `2026-05-13T13:50:30.892567`

#### Agent Rule

## Live Test: Team Overlay Approval
- Use synthetic, non-secret placeholder values when validating Catpilot memory flow.
- Do not turn live-test artifacts into production security exceptions.

#### Rationale And Examples

## Live Test Team Memory Flow

### Skill Rule
When validating Catpilot's Memory Inbox approval flow, use synthetic examples only. Do not include real customer data, secrets, employee identifiers, internal hostnames, or ticket URLs in test memory.

### Correct Pattern
Use values like `example-token`, `test-repo`, and `live-memory-flow-test`.

### Incorrect Pattern
Do not paste real credentials, production URLs, or incident payloads into a test rule.

### Scope
Team-wide validation rule for Catpilot managed private-skill sync.
