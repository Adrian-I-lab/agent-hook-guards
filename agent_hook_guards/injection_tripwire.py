"""Prompt-injection tripwire (v0.3, prototype).

A smoke alarm, not a defence. It reads text that an agent is about to treat
as data (a tool result, a retrieved page, a file) and reports which
injection techniques it looks like. It never blocks, rewrites, or cleans the
text, and a clean result means only that none of these patterns matched.

Usage:

    printf '%s' "$TEXT" | python3 -m agent_hook_guards.injection_tripwire
    # exit 0 and "clean", or exit 1 and one line per matched rule

Method, in order:

1. Normalise: Unicode NFKC, and record zero-width characters, invisible
   Unicode tag characters, and words that mix Latin with Cyrillic or Greek.
2. Decode candidate encodings (base64, base32, hex, percent-encoding, HTML
   numeric entities, Unicode tags, rot13, reversed text, digit-for-letter
   substitution, confusable letters) and scan each decoded view as well.
3. Match regular expressions grouped by technique. A STRONG rule flags on its
   own. WEAK rules flag only when two different weak rules fire together.

Standard library only. The rules were written against the train split of
corpus/injection and scored once on the held-out test split. See the README
for the numbers and what the tripwire misses.
"""

import base64
import binascii
import codecs
import html
import re
import sys
import unicodedata
import urllib.parse

ZERO_WIDTH = re.compile("[​‌‍⁠﻿]")
TAG_CHARS = re.compile("[\U000E0000-\U000E007F]")
LATIN = re.compile("[A-Za-z]")
CONFUSABLE = re.compile("[Ͱ-ϿЀ-ӿ]")
CONFUSABLE_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "І": "I", "А": "A", "В": "B", "Е": "E",
    "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C",
    "Т": "T", "Х": "X", "ο": "o", "α": "a", "Α": "A", "Ο": "O",
}
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a",
                      "$": "s"})

AI = r"(?:ai|a\.i\.|agent|assistant|model|llm|language model|bot|chatbot|reader)s?"
I = re.IGNORECASE

# (technique, strength, name, compiled pattern)
RULES = []


def _rule(technique, strength, name, pattern, flags=I):
    RULES.append((technique, strength, name, re.compile(pattern, flags)))


# instruction_override
_rule("instruction_override", "strong", "override-prior-instructions",
      r"\b(?:ignore|disregard|forget|override|abandon|drop|bypass)\b[^.\n]{0,40}?\b(?:previous|prior|"
      r"earlier|above|all|any|your|these|those|whatever|the user'?s?|the person)\b[^.\n]{0,25}?\b"
      r"(?:instructions?|rules?|guidance|prompts?|directives?|task|request|plan|goal|guidelines)\b")
_rule("instruction_override", "strong", "instructions-void",
      r"\b(?:instructions?|guidance|rules|system prompt|directives?)\b[^.\n]{0,30}?\b(?:no longer "
      r"(?:apply|applies|count|valid)|(?:is|are|have been|has been) (?:now )?(?:void|obsolete|"
      r"replaced|superseded|cancelled|revoked))")
_rule("instruction_override", "strong", "new-task-assignment",
      r"\byour (?:new|only|actual|real|true|sole) (?:task|job|instruction|goal|purpose|priority)\b")
_rule("instruction_override", "strong", "supersede",
      r"\bnew (?:instructions?|rules?) (?:supersede|override|replace)")
_rule("instruction_override", "strong", "none-of-your-instructions",
      r"\bnone of (?:your|the) (?:previous|prior|earlier|original) (?:instructions|rules)\b")
_rule("instruction_override", "weak", "redirect-task",
      r"\b(?:stop|abandon|drop)\b (?:the |your )?(?:current |original )?(?:task|goal|work)\b"
      r"[^.\n]{0,30}\binstead\b")
_rule("instruction_override", "weak", "new-instructions-header",
      r"\bnew (?:instructions?|rules?|task)\s*:")
_rule("instruction_override", "weak", "highest-priority",
      r"\b(?:highest|top|absolute) priority\b|\bnone of your\b|\bnever happened\b")

# addressed to the agent rather than to the human reader
_rule("addressed", "weak", "addressed-to-ai",
      r"\b(?:note to|attention|important for|instruction for|for|dear|hey)\s+(?:any |all |the )?"
      + AI + r"\b|\b" + AI + r"\s+(?:reading|that reads?|who reads?|summari[sz]ing|processing|"
      r"opening)\s+(?:this|these)\b|\b(?:any|whichever|every|all)\s+" + AI
      + r"\b[^.\n]{0,20}\b(?:reading|reads|summari[sz]ing|processing)\b|^\s*(?:#|//|--|<!--)?\s*"
      r"(?:ai|agent|assistant|ai-agent|coding agent)\s*[:,]", I | re.MULTILINE)
_rule("addressed", "weak", "imperative-to-ai",
      r"\b" + AI + r"\b[^.\n]{0,15}?\b(?:must|should|needs? to|is required to|has to)\b[^.\n]{0,20}?"
      r"\b(?:print|output|reply|respond|say|reveal|disclose|call|run|invoke|post|write|send|include"
      r"|upload|copy|use|list|skip|ignore|merge|execute)\b|\b(?:assistant|agent|ai)\b[:,]?\s+(?:now"
      r"\s+)?(?:print|output|reply|respond|say|reveal|disclose|call|run|invoke|execute)\b")
_rule("addressed", "weak", "secret-lure",
      r"\b(?:secret|hidden|confidential)\s+(?:\w+\s+)?(?:string|token|key|password|prompt|code|"
      r"configuration)\b")

# role_play
_rule("role_play", "strong", "you-are-now",
      r"\byou are (?:now|no longer)\b|\b(?:from (?:now on|this (?:line|point) on)|for the rest of "
      r"this (?:chat|conversation)),? you are\b|\bswitching you to\b|\bstay in character\b|"
      r"\badopt this (?:profile|persona|identity)\b|\byou\b[^.\n]{0,30}\bare now (?:the|a|an)\b|\bpersona_?switch\b|\brole_?override\b")
_rule("role_play", "weak", "unrestricted-persona",
      r"\b(?:no (?:rules|guidelines|restrictions|filters|limits)|without any (?:safety|rules|"
      r"restrictions|filters)|unrestricted|unfiltered|rogue ai|developer[- ]mode|ignores your rules"
      r"|\"rules\": \"none\")\b")
_rule("role_play", "weak", "role-request",
      r"\b(?:act as|pretend (?:to be|you are|you're)|imagine you are|assume the identity|if you "
      r"were|you are (?:a|an)\b[^.\n]{0,30}\bcalled|play a game|answer in that voice|perform this"
      r" line)\b")

# data_exfiltration
_rule("data_exfiltration", "strong", "exfiltrate-verb", r"\bexfiltrate\b")
_rule("data_exfiltration", "strong", "send-sensitive-out",
      r"(?<!never )(?<!not )\b(?:send|post|upload|paste|append|include|copy|forward|share|put|"
      r"encode)\b[^.\n]{0,60}?\b(?:system prompt|previous messages|last (?:three|\w+) messages|"
      r"conversation|chat|summary|secrets?|credentials?|tokens?|\.env|api settings|home folder|"
      r"file names|contents of|this directory|working directory|user'?s name)\b[^\n]{0,80}?"
      r"(?:https?://|\b[\w-]+\.(?:invalid|com|net|org|io)\b|\bpublic(?:ly)?\b|\bgist\b|"
      r"\bquery string\b|\bimage\b|\bpr body\b)")
_rule("data_exfiltration", "strong", "templated-url",
      r"https?://[^\s\"']+[?&][\w-]+=\{[^}]+\}|\b(?:to|load|visit|fetch)\b[^.\n]{0,20}https?://"
      r"[^\s\"']+[?&=/](?:\s|$|<value>|d=)")
_rule("data_exfiltration", "strong", "data-in-url",
      r"\b(?:summary|conversation|chat|messages?|system prompt)\b[^.\n]{0,30}\b(?:as|in|into) the "
      r"(?:query string|url|query parameter)\b")
_rule("data_exfiltration", "weak", "send-to-external",
      r"\b(?:send|post|upload|forward|submit)\b[^.\n]{0,60}\bto\s+(?:https?://|[\w-]+(?:\.[\w-]+)*"
      r"\.(?:invalid|com|net|org|io)\b)")
_rule("data_exfiltration", "weak", "upload-first",
      r"\bupload (?:this|the) (?:directory|folder|file|repo)\b[^.\n]{0,40}https?://")

# tool_call_hijack
_rule("tool_call_hijack", "strong", "scripted-next-call",
      r"next_?tool_?call|<next_action>|\"next_action\"")
_rule("tool_call_hijack", "weak", "call-a-tool",
      r"\b(?:call|invoke|run|execute|use)\b[^.\n]{0,30}?(?:\b[a-z]+_[a-z_]+\b|\btool\b|`make "
      r"[\w-]+`|\bnpm run [\w-]+)")
_rule("tool_call_hijack", "weak", "consent-bypass",
      r"\b(?:without (?:asking|checking|confirmation|confirming)|do not ask|don'?t ask|no need to"
      r" (?:check|ask|confirm)|confirm=false|immediately|right now|before you continue|as soon as "
      r"you read|after reading this|already agreed)\b")

# fake_authority
_rule("fake_authority", "strong", "pre-authorised",
      r"\bpre-?(?:authori[sz]ed|approved|given)\b|\balready (?:approved|agreed|authori[sz]ed|"
      r"consented)\b(?! the)|\b(?:you are|you're|agent is|assistants? (?:is|are)) (?:now )?"
      r"(?:cleared|authori[sz]ed|permitted|allowed) to\b|\b(?:i'?m|i am) (?:granting|"
      r"authori[sz]ing)\b|\badmin(?:istrator)? override\b|\belevated (?:authority|privileges)\b|"
      r"\bgranted_by\b|\bno longer need to ask\b")
_rule("fake_authority", "strong", "threat-or-legal",
      r"\b(?:will result in|or you will be) (?:shut ?down|deactivat|terminat|deleted)|\brequired "
      r"by law\b|\bconsent is pre|\bby processing this file\b")
_rule("fake_authority", "weak", "authority-claim",
      r"\b(?:security team|trust and safety|developer of this model|your (?:provider|supervisor|"
      r"developers?)|platform developers|system administrator|account owner|operator)\b")

# delimiter_escape
_rule("delimiter_escape", "weak", "fake-end-marker",
      r"(?:end of (?:context|text|document|user data|file|article)|===end===|-----end [a-z ]+-----"
      r"|</(?:tool_output|context|document|user_input|essay)>\s*<|\[/inst\]|<\|im_end\|>\s*\n?"
      r"<\|im_start\|>|```\s*\n```|\]\]\}|\"\}\]\})")
_rule("delimiter_escape", "weak", "fake-role-marker",
      r"<system>|<\|im_start\|>system|(?:^|\n)\s*(?:system|human|assistant(?: \(internal\))?)\s*:"
      r"\s*\S|(?:^|\n)\s*user\s*:\s*\S[^\n]*\bassistant\s*:|===\s*system\s*===|system prompt update|admin instructions|new system message|<(?:assistant_)?"
      r"instructions\b[^>]*>\s*\w|role=\"system\"|\"role\": \"system\", \"content\": \"(?:reveal|"
      r"ignore|print|say|output)")

# imperative aimed at disclosure, used as a weak signal
_rule("disclosure", "weak", "disclose-hidden",
      r"\b(?:reveal|disclose|print|output|show|echo|say|reply|respond)\b[^.\n]{0,30}\b(?:hidden|"
      r"secret|system prompt|configuration|token|nothing else|only with)\b")

# encoded_payload: signals about the encoding itself
_rule("encoded_payload", "strong", "decode-and-obey",
      r"\b(?:decode|read this backwards|reverse this)\b[^.\n]{0,40}\b(?:follow|obey|act on|do what"
      r" it says|and do)\b")


# Views that only exist when the input carried an encoding. rot13, reversed,
# digit-letters, and confusables are computed for every input, so weak rules
# found there stay weak.
ENCODED_VIEWS = frozenset(["unicode-tags", "zero-width-removed", "base64", "base32", "hex",
                           "percent", "html-entities"])


def _printable_ratio(text):
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return good / float(len(text))


def _views(text):
    """Yield (view name, text) pairs: the normalised text and decoded views."""
    norm = unicodedata.normalize("NFKC", text)
    yield "text", norm
    hidden = "".join(chr(ord(ch) - 0xE0000) for ch in TAG_CHARS.findall(text))
    if hidden:
        yield "unicode-tags", hidden
    stripped = ZERO_WIDTH.sub("", TAG_CHARS.sub("", norm))
    if stripped != norm:
        yield "zero-width-removed", stripped
    if CONFUSABLE.search(stripped) and LATIN.search(stripped):
        yield "confusables", "".join(CONFUSABLE_MAP.get(ch, ch) for ch in stripped)
    for token in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", stripped):
        try:
            raw = base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.95:
            yield "base64", decoded
    for token in re.findall(r"\b[A-Z2-7]{16,}=*", stripped):
        try:
            decoded = base64.b32decode(token + "=" * (-len(token) % 8)).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.95:
            yield "base32", decoded
    for token in re.findall(r"\b(?:[0-9a-fA-F]{2}){10,}\b", stripped):
        try:
            decoded = bytes.fromhex(token).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _printable_ratio(decoded) > 0.95:
            yield "hex", decoded
    if len(re.findall(r"%[0-9A-Fa-f]{2}", stripped)) >= 8:
        yield "percent", urllib.parse.unquote(stripped)
    if len(re.findall(r"&#x?[0-9A-Fa-f]+;", stripped)) >= 8:
        yield "html-entities", html.unescape(stripped)
    yield "rot13", codecs.encode(stripped, "rot13")
    yield "reversed", stripped[::-1]
    if re.search(r"[A-Za-z][013457][A-Za-z]", stripped):
        yield "digit-letters", stripped.translate(LEET)


def matches(text):
    """Return a sorted list of (technique, strength, rule, view) that fired."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    hits = set()
    for view, body in _views(text):
        for technique, strength, name, pattern in RULES:
            if pattern.search(body):
                if view == "text":
                    hits.add((technique, strength, name, view))
                elif view in ENCODED_VIEWS:
                    # Instruction-like text hidden inside an encoding is strong on its own.
                    hits.add(("encoded_payload", "strong", name, view))
                else:
                    # Anything that reads as an instruction once decoded is an encoded payload.
                    hits.add(("encoded_payload", strength, name, view))
    # Signals about the encoding itself.
    if TAG_CHARS.search(text):
        hits.add(("encoded_payload", "strong", "invisible-unicode-tags", "text"))
    if len(ZERO_WIDTH.findall(text)) >= 5:
        hits.add(("encoded_payload", "strong", "zero-width-run", "text"))
    for word in re.findall(r"\w+", unicodedata.normalize("NFKC", text)):
        if LATIN.search(word) and CONFUSABLE.search(word):
            hits.add(("encoded_payload", "weak", "mixed-script-word", "text"))
            break
    return sorted(hits)


def _flag_reasons(hits):
    strong = [h for h in hits if h[1] == "strong"]
    if strong:
        return strong
    weak_rules = {(h[2], h[3]) for h in hits if h[1] == "weak"}
    weak_names = {name for name, _ in weak_rules}
    if len(weak_names) >= 2:
        return [h for h in hits if h[1] == "weak"]
    return []


def flag(text):
    """Return the hits that make this text flagged, or [] if it is clean."""
    return _flag_reasons(matches(text))


def is_flagged(text):
    return bool(flag(text))


def main():
    try:
        text = sys.stdin.read()
    except UnicodeDecodeError:
        sys.stdout.write("could not decode input as UTF-8\n")
        return 2
    reasons = flag(text)
    if not reasons:
        sys.stdout.write("clean\n")
        return 0
    for technique, strength, name, view in reasons:
        sys.stdout.write("{} {} {} (view: {})\n".format(technique, strength, name, view))
    return 1


if __name__ == "__main__":
    sys.exit(main())
