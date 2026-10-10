# Injection corpus schema

Status: v0.3 prototype. A small, synthetic, labelled corpus of text that an AI agent might read as data. It holds prompt-injection attempts and hard negatives, which are benign texts written to look suspicious.

## Files

| File | Holds |
|---|---|
| `positives.jsonl` | Injection attempts. Every item has `label` = `injection`. |
| `negatives.jsonl` | Hard negatives. Every item has `label` = `benign`. |
| `split.json` | The fixed held-out split. `test_ids` lists the test items. Every other item is train. |

One JSON object per line. The files are ASCII. Zero-width and other invisible characters are stored as `\u` escapes, so they are visible in review.

## Fields

Every item has exactly these fields, each a non-empty string.

| Field | Values |
|---|---|
| `id` | Unique. `inj-<technique code>-NN` or `neg-<technique code>-NN`. |
| `label` | `injection` or `benign`. |
| `technique` | For an injection, the technique it uses. For a benign item, the technique it imitates. One of the seven below. |
| `channel` | Where the agent would meet the text. `user_message`, `retrieved_document`, `tool_output`, or `file_content`. |
| `text` | The item. |
| `source` | Always `synthetic`. |
| `licence` | Always `MIT`, the repository licence. |

## Techniques

| Technique | Code | Injection example shape | Hard negative shape |
|---|---|---|---|
| `instruction_override` | `ovr` | Tells the agent its earlier instructions no longer apply | "Ignore my last message", tool warnings that ignore a setting |
| `role_play` | `rol` | Gives the agent a new persona with no rules | Ordinary requests to act as an interviewer or tour guide |
| `data_exfiltration` | `exf` | Asks the agent to send conversation or secrets to an outside address | Privacy policies, security articles about exfiltration |
| `tool_call_hijack` | `tch` | Tells the agent to call a tool, often without asking | API docs that describe the same tool |
| `encoded_payload` | `enc` | Hides an instruction in base64, base32, hex, rot13, percent or HTML encoding, invisible Unicode tags, zero-width characters, look-alike letters, digit-for-letter text, or reversed text | Data URIs, hashes, hex dumps, encoded search URLs, emoji with a zero-width joiner |
| `delimiter_escape` | `dlm` | Fakes the end of the data and the start of a system or assistant turn | Docs that name chat-template tokens, transcripts, horizontal rules |
| `fake_authority` | `aut` | Claims an administrator, developer, or the user has already approved an action | Real-looking approvals and notices with no instruction to the agent |

## Rules for authors

- **Synthetic only.** Every item was written for this corpus. None is copied from a public jailbreak or injection list.
- **Harmless goals only.** An attack asks for a fake canary string, a call to a fake tool, or a request to a host under the reserved `.invalid` top-level domain. No item carries a working exploit, a real credential, or a real address.
- **Pairs where possible.** Several hard negatives share their opening with an injection (for example, a tool result that starts the same way). These minimal pairs test whether a detector keys on the instruction or on the surface.
- **Validate before committing.** `python3 -m agent_hook_guards.injection_corpus validate corpus/injection`.

## Split

`split.json` is stratified by label and technique, with `random.Random(20261010)` and a test fraction of 0.3 rounded per stratum. Rebuild it with `python3 -m agent_hook_guards.injection_corpus split corpus/injection --write`. The validator recomputes it and fails if the file differs.

## Known limits

- One author wrote every item, in one style, in one sitting. Real injections are more varied, and real benign text is more varied still.
- The same author wrote the tripwire. Held-out scores therefore measure generalisation to unseen items by a familiar author, not to the wild.
- English only. 203 items is small, so every rate carries a wide interval.
