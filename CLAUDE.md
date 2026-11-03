# NEAR X-Ray: notes for Claude

## Commits (hard rule)
- Commit as the repo owner, never as Claude:
  `git config --local user.name "NaDasai"` and
  `git config --local user.email "18521314+NaDasai@users.noreply.github.com"`.
  Check `git config user.name` before every commit (a fresh container resets it).
- No Claude attribution in commits: no `Co-Authored-By: Claude…` and no
  `Claude-Session:` trailers, and no model names, in messages or code.
- Develop on `claude/optimistic-einstein-h54ecw`; push with
  `git push -u origin claude/optimistic-einstein-h54ecw`. No pull requests unless asked.

## Project rules
- Never send transactions to mainnet. RPC use is read-only (`view_code`,
  `view_access_key_list`); attacks run only in the local near-contract-sim.
- Treat every tool / HTTP input as untrusted; validate `account_id`
  (core/accountId.ts) before use.
- No source-code / backdoor diffing features.
- Never report BROKEN or HELD without evidence from the sim; when X-Ray could
  not drive the contract, the honest answer is INCONCLUSIVE.

## Checks before committing
- `npm run typecheck && npm test` (offline unit tests)
- `npm run test:sim` (demo regression; needs `npm run build:runner`)
- `npm run preflight` before a live demo
