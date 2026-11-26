# 0010. Validators for Spanish ids, IBAN, cards, phones and email

- **Status:** Accepted
- **Date:** 2026-11-26

## Context

Annex F.4 and F.5 of the design document define the check of each class (`es_id`, `iban`, `card`, `phone`, `email`) and Annex G.1 gives the golden cases. Implementing them leaves several points open:

- **Boundaries.** The `regex` crate has no look-around, so "not part of a longer number or word" must be checked in code. Without a rule, `9912345678Z` or `4111111111111111` followed by more digits would be reported.
- **Separators.** F.4 allows "space, hyphen or dot" in ids, F.5 allows "spaces or hyphens" in cards and "optional separators" in phones, without saying where they may appear or how many.
- **Numbers next to numbers.** A card followed by its security code (`4111 1111 1111 1111 123`) is one run of digit groups with 19 digits. Taken as a whole it fails Luhn, and the card is missed.
- **Overlaps between classes.** Aggregation (ADR 0008) merges overlapping findings of one class, and drops a `secret_candidate` that overlaps a `secret`. With the new validators, four digit groups inside an IBAN can pass Luhn as a card, and nine digits inside a card can look like a phone. Section "Motor de detección" of the design says that on overlap "the most confident one wins", but no confidence values are set.
- **IBAN countries.** F.5 checks "the length of the country (24 for ES)" but gives no table of lengths.
- **The email pattern,** described only as "a simple `local@domain.tld`".

## Decision

### Candidates: groups and windows

1. **Groups.** In the normalized text, a *chunk* is a run of ASCII letters and digits split by single separators: `[A-Za-z0-9]+([ .-][A-Za-z0-9]+)*`. Each run of letters and digits in it is a *group*. Two separators in a row, or any other character, end the chunk.
2. **Windows.** A candidate is a window of **consecutive whole groups** of a chunk. A group is never split, so a value glued to other letters or digits (`9912345678Z`, `ref12345678Z`) is never reported. That is the word boundary the `regex` crate cannot express.
3. **Longest window first.** Each validator walks the groups from left to right. At each group it takes the longest window it accepts, reports it, and continues after its last group. If no window is accepted, it moves to the next group. With a card and its security code, the 16-digit window passes Luhn and is reported.
4. **Bounded work.** A window grows only while its length without separators is at most the longest value of its class: 9 for `es_id`, 34 for `iban`, 19 for `card`, 13 for `phone` (`0034` and 9 digits). The work stays linear in the text.
5. **Separators each class accepts** inside a window. A window that uses any other separator is rejected:

   | Class | Separators |
   | --- | --- |
   | `es_id` | space, `-`, `.` (`12.345.678-Z`) |
   | `iban` | space (the printed form, groups of four) |
   | `card` | space, `-` |
   | `phone` | space, `-` |

   Phones do not accept `.`, because in Spain the dot is the thousands separator. Otherwise `612.345.678 €` would be reported as a phone.
6. **Case.** Letters in ids and IBANs are accepted in upper or lower case (F.4, F.5).

### Checks

7. **`es_id`**, exactly as F.4:
   - DNI: 8 digits and the letter of `TRWAGMYFPDXBNJZSQVHLCKE`[number mod 23].
   - NIE: `X`, `Y` or `Z` (0, 1 or 2), 7 digits and the letter, computed like a DNI.
   - CIF: a letter of `ABCDEFGHJNPQRSUVW`, 7 digits and the control. The control is a digit with `A`, `B`, `E` or `H`, a letter with `N`, `P`, `Q`, `R`, `S` or `W`, and either with the rest.

   Rules: `es_id.dni`, `es_id.nie`, `es_id.cif`.
8. **`iban`:** two letters, two check digits and the account, with the length of that country in the SWIFT IBAN Registry. The lengths are transcribed from the registry when the code is written, and the registry's release is recorded next to the table, as was done for secret patterns in ADR 0008. Then mod 97 = 1, computed in chunks (F.5). An unknown country code is not an IBAN. Rule: `iban.mod97`.
9. **`card`:** 13 to 19 digits that pass Luhn. Rule: `card.luhn`.
10. **`phone`:** 9 digits starting with 6, 7, 8 or 9, optionally preceded by `0034` or by `34` with a `+` right before it. A window that starts with `34` without the `+` is not a phone. The `+` is included in the span. Rule: `phone.es`.
11. **`email`:** a pattern, not windows, because an address contains `@` and dots:

    ```text
    [A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,63}
    ```

    The match is rejected if the character before it belongs to the local part, or the character after it is a letter, a digit or `-`. Rule: `email.address`.

### Confidence and overlaps

12. **Confidence:**

    | Class | Value | Why |
    | --- | --- | --- |
    | `iban` | 95 | Country length and mod 97: a random value passes about 1 time in 97 |
    | `es_id` | 90 | Control letter or digit: 1 in 23 (DNI, NIE) or 1 in 10 (CIF) |
    | `card` | 85 | Luhn: 1 in 10 |
    | `email` | 80 | Format only, but the shape is distinctive |
    | `phone` | 60 | Format only: nine digits that start with 6 to 9 are also order numbers or references |

13. **Overlaps between `iban`, `es_id`, `card` and `phone`:** when findings of these classes overlap in the same text, only the most confident one is kept. The others are coincidences of digits inside a longer value: a phone inside a card, or a card inside an IBAN. This applies the rule of section "Motor de detección" to these four classes only.
14. **Every other overlap keeps both findings.** An `email` that contains a DNI (`12345678Z@example.com`) yields `email` and `es_id`. Both values are real personal data, and policy combines their actions. The rules of ADR 0008 for `secret`, `secret_candidate` and `invisible_text` do not change.

## Consequences

- The G.1 rows pass as written: `12345678Z`, `X1234567L`, `Y7654321G`, `B12345674`, `Q2826000H`, `ES91 2100 0418 4502 0005 1332`, `4111 1111 1111 1111` and `+34 612 345 678` are found, and the rows marked "No" are not.
- NFKC (ADR 0008) turns full-width digits and letters into ASCII, so `１２３４５６７８Ｚ` is found. A DNI written as spaced single digits (`1 2 3 4 5 6 7 8 Z`) is found too, because each digit is a group.
- A card inside an IBAN is reported as `iban` and gets the IBAN's action (`redact` by default), not the card's (`block`). That is intended: the value is an IBAN.
- Known gaps, to be listed in the threat model:
  - values glued to letters or digits (`DNI12345678Z`) are not found;
  - digits from other scripts that NFKC does not map to ASCII are not read;
  - addresses written as `name [at] example [dot] com`, and addresses with non-ASCII characters, are not found;
  - Spanish landlines are found, but foreign phone numbers are not.
- `phone` will be the main source of false positives. The accuracy corpus (M6) measures it, and its action can be lowered to `flag` per principal.
