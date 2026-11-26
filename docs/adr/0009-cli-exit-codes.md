# 0009. Exit codes of the command line

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Scripts, CI jobs and git hooks read only the exit code of a command, not its text. The design document lists the commands (Annex H) but not what they return.

Until now every command returned 0 on success and 1 on any error. That works for `run` and `key create`, but not for commands whose job is to **check** something:

- `resguardo scan` (M2.4) returned 0 after any completed scan, so a pre-commit hook passed even when a secret was found.
- If findings returned 1, they would be indistinguishable from errors: "there is a secret" and "the input could not be scanned" would be the same result, and a caller that treats "not 1" as clean would fail open.
- `config check` returned 1 both for an invalid configuration and for a file that could not be read.
- `verify-log` (M5) will need to tell a tampered log from an unreadable one.

A scan can also finish **incomplete**: a limit flag (ADR 0008) means some text was not fully decoded or checked, so the absence of findings proves nothing.

## Decision

One rule for every command:

| Code | Meaning |
| --- | --- |
| 0 | The command did its job and the answer is yes |
| 1 | The command did its job and the answer is no |
| 2 | The command could not do its job |

Per command:

| Command | 0 | 1 | 2 |
| --- | --- | --- | --- |
| `scan` | No findings and no flags | At least one finding **or** one limit flag | Unreadable file, input over the limit, invalid UTF-8, pipeline error |
| `config check` | Valid configuration (warnings allowed) | Syntax error or invalid values | File cannot be read |
| `verify-log` (M5) | Chain, signatures and sequence verify | Any of them does not | Log or public key cannot be read |
| `run`, `key create`, `init` | Finished normally | Not used | Any error |

1. **Invalid arguments are 2** for every command, which is what `clap` already returns.
2. **Flags count as 1, not 0.** An incomplete scan is never reported as clean.
3. **Warnings do not change the code.** They are printed on stderr.
4. **Text output does not depend on the code.** A command with a 1 prints the same report it would print anyway.

This follows the convention of `grep` and `diff` (0 no match, 1 match, 2 trouble).

## Consequences

- `resguardo scan --file x || exit 1` works in a hook or CI job without parsing the output, and an error stops it too.
- A caller that needs to tell "found something" from "could not check" tests for 1 or 2.
- A text that only raises a flag (for example a long, deeply encoded blob) stops a hook. That is intended: the remedy is to look at it, not to let it through.
- Errors that used to return 1 (a missing configuration file, a failed `run`) now return 2. There are no released versions, so no script depends on the old codes.
