# Scan Workflow — Full Process

**Status:** Planning
**Purpose:** Define end-to-end scan lifecycle, from initiation through PCI quarterly submission

---

## Core Flow

```
USER                          SYSTEM                          QSA
─────                         ──────                          ───

[1] Initiate scan on target
        │
        ▼
        ──────────────────►  Run scan modules (10 checks)
                             Generate immutable result
                             Status: PASS or FAIL
                             │
                             ├───── PASS ─────────────────►  [QSA review]
                             │                                │
                             │                                ▼
                             │                              Approve → Submitted ✓
                             │                              Reject  → back to user
                             │
                             ▼
                          FAIL
                             │
                             ▼
                       OPEN TASK created
                      "Site X has failed"
                             │
                             ▼
                   ┌─────────┴─────────┐
                   │                   │
              User chooses:            │
                   │                   │
                   ▼                   ▼
          Whitelisting             Rescan
          request                  (fresh scan)
                   │                   │
                   ▼                   │
              Reasoning                │
              submitted                │
                   │                   │
                   ▼                   ▼
              ──────────────────►  QSA review
                                   │
                            ┌──────┴──────┐
                            │             │
                         Approve       Reject
                            │             │
                            ▼             ▼
                       QSA submit    Task REOPENS
                                     (scan cycle dead,
                                      must rescan)
                                                     │
                                                     ▼
                                              Back to top
                                           (new scan runs,
                                            new PASS/FAIL)
```

## Key Principles

- **Results are immutable** — write-once, cannot append or modify
- **Each result carries PASS/FAIL status** — drives workflow
- **No second chance on whitelist rejection** — QSA rejects whitelist → that scan cycle dies, user must start fresh scan
- **Scans can stay open for years** — no auto-expiration

## Task States per Site

| State | Meaning | Who acts |
|-------|---------|----------|
| **OPEN** | Scan failed, pending action | User (whitelist or rescan) |
| **PENDING_QSA** | Whitelist submitted, awaiting review | QSA |
| **QSA_REJECTED** | Whitelist denied, must rescan | User forced back to rescan |
| **QSA_APPROVED** | Whitelist accepted, forwarded | System → submission |
| **SUBMITTED** | QSA processed, complete | Closed |

## Persistent Nag Rules

- Every login → show count of OPEN tasks
- OPEN tasks never auto-close
- Tasks can stay open for years
- Rescan creates new result; if FAIL again → new OPEN task
- If PASS → task closes, moves to submission flow

---

## Quarterly Tracking (CYA Compliance)

**Purpose:** Liability protection. When client complains "why didn't my service pass PCI?", show them the paper trail: "Here's every quarter you were supposed to pass. We sent reminders at 30/20/10 days. You had failed sites. You chose to rescan or whitelist. You didn't get it done. Here's the proof we tried."

### Table A: Historical Record (`server_quarterly_status`)

**Permanent record** of every server's quarterly status.

| Field | Purpose |
|-------|---------|
| hostname / IP | The server |
| year + quarter | 2026-Q1, 2026-Q2, etc. |
| status | PASS / FAIL / LATE / MISSING |
| report_id | Link to passing scan (if PASS) |
| reminder_30_sent | Bool + date |
| reminder_20_sent | Bool + date |
| reminder_10_sent | Bool + date |

- Doesn't track "gaps" or "4 consecutive passes" — just records what happened
- Grows forever (7-year retention matches PDPA)
- Purpose: **CYA (Cover Your Ass)** when client complains

### Table B: Current Quarter Queue (`quarter_scan_queue`)

**Ephemeral.** Only holds what's pending THIS quarter.

| Field | Purpose |
|-------|---------|
| hostname / IP | Server waiting to scan |
| quarter_deadline | When this quarter closes |
| reminder_30 | Sent? (bool + date) |
| reminder_20 | Sent? |
| reminder_10 | Sent? |
| status | PENDING / SCANNING / PASS / FAIL |

- Resets at quarter end (entries archive to Table A)
- Purpose: operators see "what's due NOW" without clutter
- No accumulation of past quarters' data

---

## Quarterly PCI Schedule

**Hard deadline:** First day of the last week of each quarter
- Q1: ~Mon of last week of March
- Q2: ~Mon of last week of June
- Q3: ~Mon of last week of September
- Q4: ~Mon of last week of December

**Consequence of missing deadline:**
- Late submission = PCI takes forever to respond
- Annual audit fails because Q4 data isn't ready
- Failed annual audit = risk of losing PCI license

**Reminder escalation (per open failed-site task):**
- 30 days before deadline: 1st reminder
- 20 days before deadline: 2nd reminder
- 10 days before deadline: 3rd reminder

---

## Annual Audit Requirement

PCI annual audit requires **4 PASS reports** — one from each quarter, minimum.
- Missing one quarter = flagged, audit risk
- Server quarterly status table provides the evidence chain
- When client complains, you show them: "You missed Q2 2026. Here's the reminder log. Here's the failed scan. Here's your whitelist rejection."

---

## Open Questions

- [ ] What happens at quarter end if tasks are still open? (Archive as MISSING?)
- [ ] Does the QSA submit what they have at deadline, or block?
- [ ] How many failed sites trigger escalation beyond user nag?
- [ ] Whitelist request format (free text? structured form? evidence attachment?)
- [ ] QSA review SLA (how fast must they respond to whitelist requests?)
