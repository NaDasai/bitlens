/**
 * NEAR account-id validation. Every account id that enters the engine (HTTP,
 * CLI, MCP) passes through here first — treat all input as untrusted.
 *
 * Rules (nearcore `AccountId`): 2..=64 chars, lowercase a-z, digits, and the
 * separators `-` `_` `.`; separators cannot be leading, trailing or doubled.
 * Implicit accounts (64 hex chars) and eth-implicit (`0x` + 40 hex) also match.
 */
const ACCOUNT_ID_RE = /^(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;

export class InvalidAccountIdError extends Error {
  readonly code = "INVALID_ACCOUNT_ID";
}

export function isValidAccountId(id: unknown): id is string {
  return (
    typeof id === "string" &&
    id.length >= 2 &&
    id.length <= 64 &&
    ACCOUNT_ID_RE.test(id)
  );
}

/** Trims, lowercases nothing (NEAR ids are case-sensitive: uppercase is invalid), validates. */
export function assertAccountId(id: unknown): string {
  const s = typeof id === "string" ? id.trim() : id;
  if (!isValidAccountId(s)) {
    throw new InvalidAccountIdError(
      `Invalid NEAR account id: ${JSON.stringify(id)}. Expected 2-64 chars of a-z, 0-9, '-', '_', '.' (e.g. "wrap.near").`,
    );
  }
  return s;
}
