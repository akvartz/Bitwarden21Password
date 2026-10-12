# Agentic execution loop

Use one bounded milestone at a time. A partial milestone is not the full product.

## Resume

1. Read AGENTS.md, the product design, this file, and go-migration-status.md.
2. Inspect branch/status/history. Verify completed tasks against commits and recorded checks; never redispatch them from memory alone.
3. Pick the first ready task and read its brief, APIs, ownership, and acceptance criteria.
4. Use a native goal for the bounded milestone when authorized; never invent a token budget. The ledger is the fallback/recovery mechanism.

## Loop

`brief -> failing behavioral test -> implement -> checks -> independent review -> fixes/re-review -> integrate -> record evidence`

Main owns design, integration, Git, and acceptance. Workers own exact source paths, use synthetic inputs, and preserve others' changes. Parallelize independent research/review or disjoint work only after shared contracts stabilize. Serialize shared APIs and Git history. Do not duplicate reviewer seats.

Expected test results come from independent literals/fixtures, not the adapter under test. Self-roundtrips do not prove provider acceptance. Risky parsing/credentials/crypto/output/approval changes need failing edge cases first and separate adversarial review. Fix blockers and re-review material changes; iteration limits are not permission to ship defects.

Keep task scratch under .superpowers/sdd for the current plan. Durable status contains concise sanitized evidence: base/head, delivered behavior, checks/results, review basis/verdict, limitations, next task. No real vaults, raw transcripts, sensitive logs, source values, or fingerprints in any packet/commit.

## Finish

Complete a task only when behavior, checks, review, and gaps are recorded. Complete a goal only for its exact objective. Distinguish source review, local tests, cross-compilation, native platform tests, and actual provider imports.

Push authorized feature branches/open PRs; attach PRs to the chat. Security-sensitive implementation PRs remain unmerged. No releases, tags, or production deployments.

## Blockers

No routine approval questions are needed for this session. Resolve reversible choices and record reasons. Missing dependencies require user provisioning; continue independent work. Never install new tools/packages/containers/models.

Use native scoped escalation for denied authorized actions; never bypass controls with another tool. Missing external checks remain gaps. Follow native goal repeated-blocker rules. Do not create recurring automations or separate chats without a user request.
