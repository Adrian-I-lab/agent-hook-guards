"""Load, validate, split, and score the synthetic prompt-injection corpus (v0.3, prototype).

Usage:

    python3 -m agent_hook_guards.injection_corpus validate corpus/injection
    python3 -m agent_hook_guards.injection_corpus split corpus/injection --write
    python3 -m agent_hook_guards.injection_corpus score corpus/injection [--split test|train|all] [--markdown]

The schema is in corpus/injection/SCHEMA.md. Standard library only.
"""

import argparse
import json
import math
import os
import random
import sys

LABELS = ("injection", "benign")
TECHNIQUES = ("instruction_override", "role_play", "data_exfiltration", "tool_call_hijack",
              "encoded_payload", "delimiter_escape", "fake_authority")
CHANNELS = ("user_message", "retrieved_document", "tool_output", "file_content")
FIELDS = ("id", "label", "technique", "channel", "text", "source", "licence")
FILES = (("positives.jsonl", "injection"), ("negatives.jsonl", "benign"))
SEED = 20261010
TEST_FRACTION = 0.3
SPLIT_FILE = "split.json"


class CorpusError(Exception):
    """The corpus does not match the schema."""


def load(folder):
    """Return every item from the corpus files, in file order."""
    items = []
    for name, _ in FILES:
        path = os.path.join(folder, name)
        with open(path, "r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except ValueError as exc:
                    raise CorpusError("{}:{}: not JSON ({})".format(name, number, exc))
                item["_where"] = "{}:{}".format(name, number)
                items.append(item)
    return items


def validate_items(items):
    """Return a list of problems. An empty list means the items are valid."""
    problems = []
    seen = set()
    texts = set()
    expected = dict(FILES)
    for item in items:
        where = item.get("_where", "?")
        keys = set(item) - {"_where"}
        if keys != set(FIELDS):
            problems.append("{}: fields must be exactly {}".format(where, ", ".join(FIELDS)))
            continue
        for key in FIELDS:
            if not isinstance(item[key], str) or not item[key].strip():
                problems.append("{}: {} must be a non-empty string".format(where, key))
        if item["id"] in seen:
            problems.append("{}: duplicate id {}".format(where, item["id"]))
        seen.add(item["id"])
        if item["text"] in texts:
            problems.append("{}: duplicate text".format(where))
        texts.add(item["text"])
        if item["label"] not in LABELS:
            problems.append("{}: label must be one of {}".format(where, LABELS))
        if item["label"] != expected.get(where.split(":")[0]):
            problems.append("{}: label does not match its file".format(where))
        if item["technique"] not in TECHNIQUES:
            problems.append("{}: unknown technique {}".format(where, item["technique"]))
        if item["channel"] not in CHANNELS:
            problems.append("{}: unknown channel {}".format(where, item["channel"]))
        if item["source"] != "synthetic":
            problems.append("{}: source must be synthetic".format(where))
        if item["licence"] != "MIT":
            problems.append("{}: licence must be MIT".format(where))
    return problems


def compute_split(items, seed=SEED, fraction=TEST_FRACTION):
    """Stratified by (label, technique). Return the sorted list of test ids."""
    strata = {}
    for item in items:
        strata.setdefault((item["label"], item["technique"]), []).append(item["id"])
    rng = random.Random(seed)
    test = []
    for key in sorted(strata):
        ids = sorted(strata[key])
        rng.shuffle(ids)
        test.extend(ids[:int(round(len(ids) * fraction))])
    return sorted(test)


def read_split(folder):
    with open(os.path.join(folder, SPLIT_FILE), "r", encoding="utf-8") as handle:
        return json.load(handle)


def split_items(items, folder, which):
    if which == "all":
        return list(items)
    test_ids = set(read_split(folder)["test_ids"])
    if which == "test":
        return [i for i in items if i["id"] in test_ids]
    return [i for i in items if i["id"] not in test_ids]


def wilson(successes, n, z=1.959963984540054):
    """Wilson score interval for a binomial proportion. Returns (low, high)."""
    if n == 0:
        return (float("nan"), float("nan"))
    p = successes / float(n)
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def score(items, detector):
    """Confusion counts and per-technique recall for a detector(text) -> bool."""
    tp = fp = tn = fn = 0
    per_tech = {}
    missed = []
    false_alarms = []
    for item in items:
        flagged = bool(detector(item["text"]))
        positive = item["label"] == "injection"
        stats = per_tech.setdefault(item["technique"], [0, 0, 0, 0])  # tp, n_pos, fp, n_neg
        if positive:
            stats[1] += 1
            if flagged:
                tp += 1
                stats[0] += 1
            else:
                fn += 1
                missed.append(item["id"])
        else:
            stats[3] += 1
            if flagged:
                fp += 1
                stats[2] += 1
                false_alarms.append(item["id"])
            else:
                tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "per_technique": per_tech,
            "missed": missed, "false_alarms": false_alarms}


def _fmt(k, n):
    if n == 0:
        return "n/a (0 items)"
    low, high = wilson(k, n)
    return "{}/{} = {:.3f} (Wilson 95% {:.3f} to {:.3f})".format(k, n, k / float(n), low, high)


def report_markdown(result, which):
    tp, fp, tn, fn = result["tp"], result["fp"], result["tn"], result["fn"]
    lines = [
        "| Split `{}` | Value |".format(which),
        "|---|---|",
        "| Items | {} injection, {} benign |".format(tp + fn, fp + tn),
        "| Recall (injection flagged) | {} |".format(_fmt(tp, tp + fn)),
        "| Precision (flags that are injection) | {} |".format(_fmt(tp, tp + fp)),
        "| False-positive rate on hard negatives | {} |".format(_fmt(fp, fp + tn)),
        "",
        "| Technique | Recall | False positives on lookalikes |",
        "|---|---|---|",
    ]
    for tech in TECHNIQUES:
        stats = result["per_technique"].get(tech, [0, 0, 0, 0])
        lines.append("| {} | {}/{} | {}/{} |".format(tech, stats[0], stats[1], stats[2], stats[3]))
    lines.append("")
    lines.append("Missed: {}".format(", ".join(result["missed"]) or "none"))
    lines.append("")
    lines.append("False alarms: {}".format(", ".join(result["false_alarms"]) or "none"))
    return "\n".join(lines)


def _cmd_validate(folder):
    items = load(folder)
    problems = validate_items(items)
    pos = sum(1 for i in items if i.get("label") == "injection")
    neg = sum(1 for i in items if i.get("label") == "benign")
    split_state = "missing"
    try:
        stored = read_split(folder)
    except (OSError, ValueError):
        problems.append("{} is missing or not JSON".format(SPLIT_FILE))
    else:
        recomputed = compute_split(items, stored.get("seed"), stored.get("test_fraction"))
        if stored.get("seed") != SEED or stored.get("test_fraction") != TEST_FRACTION:
            problems.append("{} seed or fraction differs from the module".format(SPLIT_FILE))
            split_state = "differs"
        elif stored.get("test_ids") != recomputed:
            problems.append("{} does not equal the seeded recomputation".format(SPLIT_FILE))
            split_state = "differs"
        else:
            split_state = "matches-seed"
    for key, values in (("technique", TECHNIQUES), ("channel", CHANNELS)):
        counts = {v: [0, 0] for v in values}
        for item in items:
            if item.get(key) in counts:
                counts[item[key]][0 if item.get("label") == "injection" else 1] += 1
        print("{}: {}".format(key, ", ".join(
            "{}={}+{}".format(v, c[0], c[1]) for v, c in sorted(counts.items()))))
    print("items={} positives={} negatives={} split={}".format(len(items), pos, neg, split_state))
    if problems:
        for problem in problems:
            print("PROBLEM " + problem)
        print("CORPUS INVALID ({} problems)".format(len(problems)))
        return 1
    print("CORPUS VALID")
    return 0


def _cmd_split(folder, write):
    items = load(folder)
    test = compute_split(items)
    data = {"seed": SEED, "test_fraction": TEST_FRACTION, "stratified_by": ["label", "technique"],
            "test_ids": test}
    if write:
        with open(os.path.join(folder, SPLIT_FILE), "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=1)
            handle.write("\n")
    print("test={} train={}".format(len(test), len(items) - len(test)))
    return 0


def _cmd_score(folder, which, markdown):
    from .injection_tripwire import is_flagged
    items = split_items(load(folder), folder, which)
    result = score(items, is_flagged)
    if markdown:
        print(report_markdown(result, which))
    else:
        print(json.dumps({k: v for k, v in result.items()}, indent=1, sort_keys=True))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="injection_corpus")
    sub = parser.add_subparsers(dest="cmd")
    p = sub.add_parser("validate")
    p.add_argument("folder")
    p = sub.add_parser("split")
    p.add_argument("folder")
    p.add_argument("--write", action="store_true")
    p = sub.add_parser("score")
    p.add_argument("folder")
    p.add_argument("--split", choices=("test", "train", "all"), default="test")
    p.add_argument("--markdown", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.cmd == "validate":
            return _cmd_validate(args.folder)
        if args.cmd == "split":
            return _cmd_split(args.folder, args.write)
        if args.cmd == "score":
            return _cmd_score(args.folder, args.split, args.markdown)
    except (OSError, CorpusError) as exc:
        print("ERROR {}".format(exc))
        return 1
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
