"""Standalone threat labeling for CSV datasets.

Reads a CSV with columns:
  Author, Texts, Language, Threat_Confidence, Threat_Level

Fills Threat_Confidence (0..1) and Threat_Level (categorical) using:
- IOC detection (regex-based)
- Language-specific threat keyword hits (Malay + English)
- Author correlation (two-pass multiplier based on how many threat posts an author has)

This file is intentionally standalone and does not import project code.
"""

from __future__ import annotations

import argparse
import csv
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Set, Tuple


# ----------------------------
# IOC detection (regex-based)
# ----------------------------

IOC_PATTERNS: Mapping[str, re.Pattern[str]] = {
    # IPv4 addresses (basic)
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    # URLs
    "url": re.compile(r"\bhttps?://[^\s\"'>)]+", re.IGNORECASE),
    # Domains (simple, avoids trailing punctuation)
    "domain": re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|io|me|co|my|uk|ru|cn|de|jp|fr|au|sg)\b", re.IGNORECASE),
    # CVE identifiers
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    # Common hashes
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.IGNORECASE),
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    # Email addresses
    "email": re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.IGNORECASE),
}

IOC_WEIGHTS: Mapping[str, float] = {
    # Note: URLs/domains are common in benign posts; keep their weight modest.
    "ipv4": 0.8,
    "url": 0.6,
    "domain": 0.4,
    "cve": 2.0,
    "md5": 3.0,
    "sha1": 3.0,
    "sha256": 3.5,
    "email": 0.2,
}


def extract_iocs(text: str) -> Dict[str, Set[str]]:
    found: Dict[str, Set[str]] = {}
    if not text:
        return found
    for name, pattern in IOC_PATTERNS.items():
        matches = set(m.group(0) for m in pattern.finditer(text))
        if matches:
            found[name] = matches
    return found


def ioc_score(iocs: Mapping[str, Set[str]]) -> Tuple[float, int]:
    score = 0.0
    count = 0
    for ioc_type, items in iocs.items():
        n = len(items)
        count += n
        score += IOC_WEIGHTS.get(ioc_type, 1.0) * n
    return score, count


# ----------------------------
# Tokenization + keyword hits
# ----------------------------

TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def tokenize(text: str) -> List[str]:
    if not text:
        return []
    return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]


@dataclass(frozen=True)
class KeywordConfig:
    weights: Mapping[str, float]

    def score_tokens(self, tokens: Sequence[str]) -> Tuple[float, int, Counter[str]]:
        if not tokens:
            return 0.0, 0, Counter()
        token_counts = Counter(tokens)
        hits = Counter()
        score = 0.0
        hit_total = 0
        for kw, w in self.weights.items():
            c = token_counts.get(kw, 0)
            if c:
                hits[kw] = c
                hit_total += c
                score += w * c
        return score, hit_total, hits


@dataclass(frozen=True)
class PhraseKeywordConfig:
    """Phrase matcher for hyphenated / multiword keywords.

    Matches are counted via regex finditer on a normalized lowercase string.
    """

    phrase_weights: Mapping[str, float]
    phrase_patterns: Mapping[str, re.Pattern[str]]

    @staticmethod
    def from_phrases(phrase_weights: Mapping[str, float]) -> "PhraseKeywordConfig":
        patterns: Dict[str, re.Pattern[str]] = {}
        for phrase, _w in phrase_weights.items():
            patterns[phrase] = _build_phrase_pattern(phrase)
        return PhraseKeywordConfig(phrase_weights=dict(phrase_weights), phrase_patterns=patterns)

    def score_text(self, normalized_text: str) -> Tuple[float, int, Counter[str]]:
        if not normalized_text:
            return 0.0, 0, Counter()
        score = 0.0
        hit_total = 0
        hits: Counter[str] = Counter()
        for phrase, w in self.phrase_weights.items():
            pat = self.phrase_patterns.get(phrase)
            if not pat:
                continue
            c = 0
            for _m in pat.finditer(normalized_text):
                c += 1
            if c:
                hits[phrase] = c
                hit_total += c
                score += w * c
        return score, hit_total, hits


def _normalize_for_phrase_match(text: str) -> str:
    return (text or "").lower()


def _build_phrase_pattern(phrase: str) -> re.Pattern[str]:
    """Build a regex that matches a phrase with flexible separators.

    Example:
      "og-kush" matches "og-kush", "og kush", "og_kush"
    """
    parts = [p for p in re.split(r"[^a-z0-9]+", phrase.lower()) if p]
    if not parts:
        return re.compile(r"a^")
    if len(parts) == 1:
        # treat as a single token-like pattern
        return re.compile(rf"\b{re.escape(parts[0])}\b", re.IGNORECASE)
    sep = r"[-_\s]+"
    body = sep.join(re.escape(p) for p in parts)
    return re.compile(rf"\b{body}\b", re.IGNORECASE)


def _dedupe_preserve_order(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for it in items:
        key = (it or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def _danger_weight(term: str) -> float:
    """Assign weights by relative danger/severity.

    Higher weight => higher contribution to Threat_Confidence.
    """
    t = term.lower()

    # Lightweight heuristics for common patterns
    if t.startswith("cve-"):
        return 2.6

    # Critical: firearms/explosives / explicit weaponry
    critical_weapons = {
        "guns",
        "weapon",
        "firearm",
        "firearms",
        "glock",
        "pistol",
        "rifle",
        "shotgun",
        "silencer",
        "ammo",
        "ammunition",
        "bullet",
        "detonator",
        "c4",
        "explosive",
        "explosives",
        "smoke-bomb",
        "switchblade",
        "taser",
        "knuckle-duster",
        "ballistic",
        "armor",
        "vest",
        # Malay
        "senjata-api",
        "peluru",
        "letupan",
        "bom-asap",
        "pisau-lipat",
    }

    # High: hard drugs / opioids / fentanyl-class
    hard_drugs = {
        "heroin",
        "fentanyl",
        "opioids",
        "opium",
        "meth",
        "crystal",
        "morphine",
        "oxycodone",
        "hydrocodone",
        "codeine",
        "tramadol",
        "suboxone",
        "methadone",
        "crack",
        "cocaine",
        "coke",
        "syabu",
        "dadah",
        "oxycontin",
        "roxy",
        "dilaudid",
        "subutex",
        "buprenorphine",
    }

    # Medium-high: controlled substances / psychedelics / benzos / stimulants
    controlled_substances = {
        "mdma",
        "ecstasy",
        "lsd",
        "lsd-25",
        "ketamine",
        "mushrooms",
        "shrooms",
        "molly",
        "dmt",
        "mescaline",
        "ayahuasca",
        "peyote",
        "salvia",
        "nitrous",
        "poppers",
        "xanax",
        "valium",
        "benzo",
        "etizolam",
        "alprazolam",
        "diazepam",
        "lorazepam",
        "temazepam",
        "ritalin",
        "modafinil",
        "adderall",
        "percocet",
        "speed",
        "benzos",
        "amphetamine",
        "mephedrone",
        "nbome",
        "steroids",
        "rcs",
        "canabinoids",
        "nootropics",
        "empathogens",
        "dissociatives",
        "clonazepam",
        "carisoprodol",
        "armodafinil",
        "sildenafil",
        "tadalafil",
        "viagra",
        "zopiclone",
        "zolpidem",
        "gabapentin",
        "pregabalin",
        # Malay
        "pil-kuda",
        "air-ketum",
        "ubat-terlarang",
        "dadah-sintetik",
    }

    # Medium: cannabis and derivatives
    cannabis_family = {
        "cannabis",
        "weed",
        "marijuana",
        "ganja",
        "kush",
        "hash",
        "resin",
        "buds",
        "seeds",
        "sativa",
        "indica",
        "thc",
        "cbd",
        "hemp",
        "edibles",
        "dabs",
        "wax",
        "shatter",
        "skunk",
        "amnesia",
        "haze",
        "gorilla-glue",
        "northern-lights",
        "og-kush",
        "white-widow",
        "sour-diesel",
        "blue-dream",
        "girl-scout-cookies",
        "concentrates",
        "bho",
        "thc-oil",
        "crumble",
        "hashish",
        "charas",
        "bubblehash",
        "kief",
        "trim",
        "shake",
        "cartridges",
        # Malay
        "ganja-hidro",
    }

    # Medium-high: fraud/identity/financial crime
    fraud_identity = {
        "carding",
        "stolen",
        "stolen-data",
        "credential",
        "credentials",
        "logs",
        "mail-logs",
        "dumps",
        "fullz",
        "ssn",
        "passport",
        "id-card",
        "license",
        "bank-login",
        "cloned-card",
        "cvv",
        "bin",
        "atm",
        "skimming",
        "skimming-device",
        "blank-cards",
        "embosser",
        "magnetic-reader",
        "cookies",
        "cash-out",
        "money-laundry",
        "clean-crypto",
        "prepaid-card",
        "gift-card",
        "paypal",
        "stripe",
        "western-union",
        # Malay terms
        "akaun",
        "kad",
        "kredit",
        "palsu",
        "penipuan",
        "counterfeits",
        "replica",
        # Malay
        "kad-klon",
        "wang-haram",
        "pembersihan-wang",
    }

    # Cyber: malware/intrusion/tooling
    cyber_high = {
        "ransomware",
        "malware",
        "botnet",
        "stealer",
        "rat",
        "backdoor",
        "rootkit",
        "trojan",
        "spyware",
        "keylogger",
        "payload",
        "zero-day-exploit",
        "cobalt-strike",
        "zero-day",
        # Malay
        "pintu-belakang",
    }

    cyber_med = {
        "hacked",
        "leak",
        "exploit",
        "phishing",
        "ddos",
        "database",
        "injection",
        "sql",
        "vulnerability",
        "bypass",
        "malicious",
        "shell",
        "bruteforce",
        "cve",
        "metasploit",
        "nmap",
        "wireshark",
        "burp-suite",
        "kali-linux",
        "pentesting",
        # Malay terms
        "bocor",
        "godam",
        "pancingan",
        "pangkalan",
        "pencerobohan",
        "tebusan",
        "fud",
        "obfuscated",
        "crypted",
        "antivirus",
        "defender",
        "sandbox",
        "virtual-machine",
        "debugger",
        "disassembler",
        "decompiler",
        "hex-editor",
        "packet-sniffer",
        "burpsuite",
        "sqlmap",
        "hydra",
        "john-the-ripper",
        "hashcat",
        "wordlist",
        "dictionary",
        "brute-force",
        "credential-stuffing",
        "account-takeover",
        "ato",
        "sim-swap",
        "otp-bypass",
        "2fa-bypass",
        "phishing-page",
        "scampage",
        "smtp",
        "mailer",
        "leads",
        "data-leak",
        "db-dump",
        "sql-dump",
        "csv-dump",
        "json-dump",
        "user-logs",
        "browser-cookies",
        "session-id",
        "api-key",
        "private-key",
        "seed-phrase",
        "mnemonic",
        "mnemonic-phrase",
        "recovery-key",
        "skrip-hasad",
        # Malay
        "ancaman",
        "mangsa",
        "umpan",
        "tembus",
        "suntikan",
        "pencurian",
        "pencuri",
        "penceroboh",
        "tembusan",
        "data-bocor",
        "akaun-digodam",
        "kerosakan",
    }

    # Marketplace ops / OPSEC / comms (lower danger individually)
    ops_low = {
        "escrow",
        "stealth",
        "stealth-packaging",
        "shipping",
        "tracked-shipping",
        "domestic-shipping",
        "worldwide-shipping",
        "express-delivery",
        "priority-mail",
        "no-signature",
        "escrow-accepted",
        "vendor",
        "darknet",
        "onion",
        "tor",
        "marketplace",
        "listing",
        "fe",
        "anonymous",
        "pgp",
        "crypto",
        "monero",
        "btc",
        "bitcoin",
        "wallet",
        "mixer",
        "underground",
        "illicit",
        "contraband",
        "courier",
        "package",
        "vacuum-sealed",
        "decoy",
        "drop",
        "feedback",
        "rating",
        "wickr",
        "telegram",
        "encrypted",
        "privnote",
        "jabber",
        "xmpp",
        "scammer",
        "ripper",
        "proxies",
        "vpn",
        "socks5",
        "rdp",
        "vps",
        "bulletproof-hosting",
        "spamming",
        "se-service",
        "social-engineering",
        "amazon-refunding",
        "combo-list",
        "email-pass",
        "reagent-test",
        "purity-test",
        "vials",
        "bottles",
        "mylar",
        "vacuumed",
        "stealthy",
        "disguised",
        "hidden",
        "concealed",
        "untraceable",
        "pgp-signed",
        "multisig",
        "escrowed",
        "blockchain",
        "confirmation",
        "transaction",
        "tumbler",
        "clearnet",
        "deepweb",
        "i2p",
        "zeronet",
        "freenet",
        "tails",
        "qubes",
        "whonix",
        "socks",
        "ssh-tunnel",
        "vps-hosting",
        "bulletproof",
        "offshore",
        "registrar",
        "nameserver",
        "whois",
        "hardware-wallet",
        "ledger",
        "trezor",
        "metamask",
        "trustwallet",
        "coinbase",
        "binance",
        "kraken",
        "kucoin",
        "bitmex",
        "localbitcoins",
        "paxful",
        "bisq",
        "monero-gui",
        "cake-wallet",
        "electrum",
        "wasabi",
        "samourai",
        "sparrow-wallet",
        "cold-storage",
        # Malay
        "peribadi",
        "sulit",
        "rahsia",
        "samaran",
        "haram",
        "jenayah",
        "siber",
        "pangkalan",
        "pelayan",
        "rangkaian",
        "tiruan",
        "palsu",
        "topeng",
    }

    # Generic/ambiguous terms (keep low)
    ambiguous_low = {
        "pills",
        "tabs",
        "buds",
        "seeds",
        "resin",
        "drop",
        "package",
        "database",
        "shell",
        "sql",
        "crypto",
        "anonymous",
        "hasad",
        "automatic",
        # Extra ambiguous / high false-positive risk
        "powder",
        "crystals",
        "tablets",
        "blotters",
        "synthetic",
        "pressed",
        "pharmaceutical",
        "lab-tested",
        "uncut",
        "potent",
        "euphoric",
        "vials",
        "bottles",
        "cartridges",
        "clones",
        "greenhouse",
        "hydroponic",
        "pesticide-free",
        "top-shelf",
        "loud",
        "dank",
        "fire",
        "gas",
        "sticky",
        "stinky",
        "smelly",
        "nepalese",
        "afghan",
        "moroccan",
        "lemah",
    }

    if t in critical_weapons:
        return 4.2
    if t in hard_drugs:
        return 3.8
    if t in controlled_substances:
        return 3.2
    if t in cannabis_family:
        return 2.4
    if t in fraud_identity:
        return 3.4
    if t in cyber_high:
        return 3.4
    if t in cyber_med:
        return 2.6
    if t in ops_low:
        return 1.2
    if t in ambiguous_low:
        return 0.8
    return 1.2


def build_universal_threat_keyword_configs() -> Tuple[KeywordConfig, PhraseKeywordConfig]:
    # Full keyword list provided by the user.
    # NOTE: Use lowercase; matching is case-insensitive.
    raw_terms = [
        "cannabis",
        "weed",
        "mdma",
        "cocaine",
        "ecstasy",
        "lsd",
        "kush",
        "hash",
        "opioids",
        "xanax",
        "heroin",
        "meth",
        "opium",
        "ketamine",
        "mushrooms",
        "pills",
        "crystal",
        "valium",
        "morphine",
        "speed",
        "ganja",
        "syabu",
        "dadah",
        "shrooms",
        "sativa",
        "indica",
        "fentanyl",
        "oxycodone",
        "tramadol",
        "percocet",
        "adderall",
        "benzo",
        "coke",
        "crack",
        "molly",
        "tabs",
        "buds",
        "seeds",
        "resin",
        "hacked",
        "leak",
        "exploit",
        "ransomware",
        "database",
        "credential",
        "phishing",
        "malware",
        "ddos",
        "carding",
        "stolen",
        "logs",
        "dumps",
        "fullz",
        "botnet",
        "stealer",
        "injection",
        "rat",
        "backdoor",
        "sql",
        "vulnerability",
        "bypass",
        "malicious",
        "spyware",
        "rootkit",
        "trojan",
        "keylogger",
        "payload",
        "shell",
        "bruteforce",
        "bocor",
        "godam",
        "hasad",
        "tebusan",
        "pancingan",
        "pangkalan",
        "akaun",
        "kad",
        "kredit",
        "pencerobohan",
        "palsu",
        "escrow",
        "stealth",
        "shipping",
        "vendor",
        "darknet",
        "onion",
        "fe",
        "listing",
        "anonymous",
        "pgp",
        "crypto",
        "monero",
        "btc",
        "bitcoin",
        "wallet",
        "mixer",
        "tor",
        "marketplace",
        "underground",
        "illicit",
        "contraband",
        "courier",
        "package",
        "vacuum-sealed",
        "decoy",
        "drop",
        "wickr",
        "telegram",
        "encrypted",
        "privnote",
        "jabber",
        "xmpp",
        "feedback",
        "rating",
        "scammer",
        "ripper",
        "ssn",
        "passport",
        "id-card",
        "license",
        "bank-login",
        "paypal",
        "stripe",
        "western-union",
        "cloned-card",
        "cvv",
        "bin",
        "atm",
        "skimming",
        "cookies",
        "rdp",
        "vps",
        "proxies",
        "vpn",
        "socks5",
        "guns",
        "fireworks",
        "weapon",
        "glock",
        "pistol",
        "ammo",
        "ammunition",
        "explosive",
        "rifle",
        "shotgun",
        "silencer",
        "automatic",
        "bullet",
        "firearm",
        "detonator",
        "c4",
        "smoke-bomb",
        "taser",
        "knuckle-duster",
        "switchblade",
        "ballistic",
        "armor",
        "vest",
        "skunk",
        "amnesia",
        "haze",
        "gorilla-glue",
        "northern-lights",
        "og-kush",
        "white-widow",
        "sour-diesel",
        "blue-dream",
        "girl-scout-cookies",
        "dabs",
        "wax",
        "shatter",
        "edibles",
        "thc",
        "cbd",
        "hemp",
        "lsd-25",
        "dmt",
        "mescaline",
        "ayahuasca",
        "peyote",
        "salvia",
        "nitrous",
        "poppers",
        "suboxone",
        "methadone",
        "ritalin",
        "modafinil",
        "etizolam",
        "alprazolam",
        "diazepam",
        "lorazepam",
        "temazepam",
        "codeine",
        "hydrocodone",
        "skimming-device",
        "blank-cards",
        "embosser",
        "magnetic-reader",
        "cash-out",
        "money-laundry",
        "clean-crypto",
        "prepaid-card",
        "gift-card",
        "amazon-refunding",
        "se-service",
        "social-engineering",
        "spamming",
        "bulletproof-hosting",
        "zero-day-exploit",
        "cve",
        "metasploit",
        "nmap",
        "wireshark",
        "burp-suite",
        "cobalt-strike",
        "kali-linux",
        "pentesting",
        "stolen-data",
        "mail-logs",
        "combo-list",
        "email-pass",
        "stealth-packaging",
        "tracked-shipping",
        "domestic-shipping",
        "worldwide-shipping",
        "express-delivery",
        "priority-mail",
        "no-signature",
        "escrow-accepted",
        "purity-test",
        "reagent-test",
        "benzos",
        "powder",
        "concentrates",
        "uncut",
        "potent",
        "crystals",
        "tablets",
        "blotters",
        "steroids",
        "counterfeits",
        "nbome",
        "bho",
        "viagra",
        "amphetamine",
        "replica",
        "fishscale",
        "speedpaste",
        "mephedrone",
        "rcs",
        "canabinoids",
        "nootropics",
        "empathogens",
        "dissociatives",
        "euphoric",
        "synthetic",
        "pressed",
        "lab-tested",
        "pharmaceutical",
        "clonazepam",
        "carisoprodol",
        "armodafinil",
        "sildenafil",
        "tadalafil",
        "zopiclone",
        "zolpidem",
        "gabapentin",
        "pregabalin",
        "subutex",
        "buprenorphine",
        "oxycontin",
        "roxy",
        "dilaudid",
        "vials",
        "bottles",
        "cartridges",
        "thc-oil",
        "crumble",
        "hashish",
        "charas",
        "nepalese",
        "afghan",
        "moroccan",
        "bubblehash",
        "kief",
        "trim",
        "shake",
        "clones",
        "greenhouse",
        "hydroponic",
        "pesticide-free",
        "top-shelf",
        "loud",
        "dank",
        "fire",
        "gas",
        "sticky",
        "stinky",
        "smelly",
        "vacuumed",
        "mylar",
        "stealthy",
        "disguised",
        "hidden",
        "concealed",
        "untraceable",
        "pgp-signed",
        "multisig",
        "escrowed",
        "blockchain",
        "confirmation",
        "transaction",
        "tumbler",
        "clearnet",
        "deepweb",
        "i2p",
        "zeronet",
        "freenet",
        "tails",
        "qubes",
        "whonix",
        "socks",
        "rdp-access",
        "ssh-tunnel",
        "vps-hosting",
        "bulletproof",
        "offshore",
        "registrar",
        "nameserver",
        "whois",
        "zero-day",
        "cve-2023",
        "fud",
        "obfuscated",
        "crypted",
        "runtime",
        "scantime",
        "antivirus",
        "defender",
        "sandbox",
        "virtual-machine",
        "debugger",
        "disassembler",
        "decompiler",
        "hex-editor",
        "packet-sniffer",
        "burpsuite",
        "sqlmap",
        "hydra",
        "john-the-ripper",
        "hashcat",
        "wordlist",
        "dictionary",
        "brute-force",
        "credential-stuffing",
        "account-takeover",
        "ato",
        "sim-swap",
        "otp-bypass",
        "2fa-bypass",
        "phishing-page",
        "scampage",
        "smtp",
        "mailer",
        "leads",
        "data-leak",
        "db-dump",
        "sql-dump",
        "csv-dump",
        "json-dump",
        "user-logs",
        "browser-cookies",
        "session-id",
        "token",
        "api-key",
        "private-key",
        "seed-phrase",
        "mnemonic",
        "mnemonic-phrase",
        "recovery-key",
        "hardware-wallet",
        "ledger",
        "trezor",
        "metamask",
        "trustwallet",
        "coinbase",
        "binance",
        "kraken",
        "kucoin",
        "bitmex",
        "localbitcoins",
        "paxful",
        "bisq",
        "monero-gui",
        "cake-wallet",
        "electrum",
        "wasabi",
        "samourai",
        "sparrow-wallet",
        "cold-storage",
        "peribadi",
        "sulit",
        "ancaman",
        "mangsa",
        "umpan",
        "tembus",
        "lemah",
        "suntikan",
        "pencurian",
        "samaran",
        "pengedar",
        "pusher",
        "haram",
        "jenayah",
        "siber",
        "pelayan",
        "rangkaian",
        "tembusan",
        "rahsia",
        "tiruan",
        "pencuri",
        "penceroboh",
        "kerosakan",
        "data-bocor",
        "akaun-digodam",
        "kad-klon",
        "wang-haram",
        "pembersihan-wang",
        "dadah-sintetik",
        "ganja-hidro",
        "pil-kuda",
        "air-ketum",
        "syabu-kristal",
        "ubat-terlarang",
        "senjata-api",
        "peluru",
        "letupan",
        "bom-asap",
        "pisau-lipat",
        "topeng",
        "pintu-belakang",
        "skrip-hasad",
    ]

    terms = _dedupe_preserve_order(raw_terms)

    token_weights: Dict[str, float] = {}
    phrase_weights: Dict[str, float] = {}

    for term in terms:
        w = _danger_weight(term)
        # If term contains separators, treat as phrase; otherwise token.
        if re.search(r"[^a-z0-9]", term):
            phrase_weights[term] = max(phrase_weights.get(term, 0.0), w)
        else:
            token_weights[term] = max(token_weights.get(term, 0.0), w)

    return KeywordConfig(weights=token_weights), PhraseKeywordConfig.from_phrases(phrase_weights)


UNIVERSAL_TOKEN_KEYWORDS, UNIVERSAL_PHRASE_KEYWORDS = build_universal_threat_keyword_configs()


EN_VIOLENCE_CYBER_KEYWORDS = KeywordConfig(
    weights={
        # explicit violence
        "kill": 3.0,
        "murder": 3.2,
        "shoot": 2.8,
        "stab": 2.6,
        "bomb": 3.5,
        "explode": 3.0,
        "attack": 2.4,
        "assassinate": 3.5,
        "hostage": 3.0,
        "kidnap": 3.0,
        "threat": 2.2,
        # cyber / abuse
        "hack": 2.4,
        "ddos": 2.8,
        "ransomware": 3.4,
        "malware": 2.8,
        "phishing": 2.6,
        "leak": 2.0,
        "breach": 2.2,
        "exploit": 2.4,
        "botnet": 2.6,
        "stealer": 2.6,
    }
)


MS_VIOLENCE_CYBER_KEYWORDS = KeywordConfig(
    weights={
        # explicit violence
        "bunuh": 3.2,
        "membunuh": 3.2,
        "tembak": 2.8,
        "tikam": 2.8,
        "bom": 3.5,
        "meletup": 3.0,
        "letup": 3.0,
        "serang": 2.4,
        "ugut": 2.6,
        "ancam": 2.6,
        "penculik": 3.0,
        "culik": 3.0,
        "tebus": 2.6,
        "pengganas": 3.2,
        "keganasan": 3.0,
        # cyber
        "godam": 2.4,
        "hack": 2.0,
        "phishing": 2.4,
        "malware": 2.6,
        "ransomware": 3.2,
        "ddos": 2.6,
        "botnet": 2.4,
        "stealer": 2.4,
    }
)



def keyword_score(text: str, language: str, tokens: Sequence[str]) -> Tuple[float, int, Counter[str]]:
    """Score keywords using language-specific + universal term lists."""
    lang = (language or "").strip().lower()
    normalized_text = _normalize_for_phrase_match(text)

    uni_tok_s, uni_tok_h, uni_tok_hits = UNIVERSAL_TOKEN_KEYWORDS.score_tokens(tokens)
    uni_phr_s, uni_phr_h, uni_phr_hits = UNIVERSAL_PHRASE_KEYWORDS.score_text(normalized_text)
    uni_tok_hits.update(uni_phr_hits)

    if lang in {"malay", "ms", "bahasa", "bahasa malay", "bahasa malaysia"}:
        s1, h1, hits1 = MS_VIOLENCE_CYBER_KEYWORDS.score_tokens(tokens)
        hits1.update(uni_tok_hits)
        return (s1 + uni_tok_s + uni_phr_s), (h1 + uni_tok_h + uni_phr_h), hits1

    if lang in {"english", "en"}:
        s1, h1, hits1 = EN_VIOLENCE_CYBER_KEYWORDS.score_tokens(tokens)
        hits1.update(uni_tok_hits)
        return (s1 + uni_tok_s + uni_phr_s), (h1 + uni_tok_h + uni_phr_h), hits1

    # fallback: treat as mixed
    ms1, mh1, _ = MS_VIOLENCE_CYBER_KEYWORDS.score_tokens(tokens)
    en1, eh1, _ = EN_VIOLENCE_CYBER_KEYWORDS.score_tokens(tokens)
    hits = Counter(uni_tok_hits)
    return (ms1 + en1 + uni_tok_s + uni_phr_s), (mh1 + eh1 + uni_tok_h + uni_phr_h), hits


# ----------------------------
# Scoring formulas
# ----------------------------

@dataclass(frozen=True)
class ScoringParams:
    # Map raw signal to base confidence (0..1)
    raw_scale: float = 10.0

    # Multipliers per hit (requirement: “multiply by 5% if IOC exists”)
    ioc_multiplier_per_hit: float = 0.05
    keyword_multiplier_per_hit: float = 0.03

    # Two-pass author correlation multiplier
    author_multiplier_per_threat_post: float = 0.02
    author_multiplier_cap: float = 0.50  # max +50%

    # Decide whether a row counts as a “threat post” for author correlation
    author_threat_conf_threshold: float = 0.55


def raw_to_confidence(raw: float, raw_scale: float) -> float:
    # Smooth saturating map: raw=0 -> 0, larger raw -> approaches 1
    if raw <= 0:
        return 0.0
    scale = max(raw_scale, 1e-9)
    return 1.0 - math.exp(-raw / scale)


def confidence_to_level(conf: float) -> str:
    # Simple, explainable thresholds
    if conf >= 0.85:
        return "Critical"
    if conf >= 0.70:
        return "High"
    if conf >= 0.50:
        return "Medium"
    if conf >= 0.25:
        return "Low"
    return "None"


_LEVEL_ORDER: Mapping[str, int] = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def confidence_to_level_capped(conf: float, max_keyword_weight: float) -> str:
    """Convert confidence to a Threat_Level, capped by keyword danger.

    This prevents common marketplace listings (e.g., logistics words) from becoming
    "Critical" purely due to many keyword hits.
    """
    level = confidence_to_level(conf)

    # Cap derived from the most dangerous matched term.
    if max_keyword_weight >= 4.0:
        cap = "Critical"  # weapons/explosives
    elif max_keyword_weight >= 3.4:
        cap = "High"  # hard drugs / fraud / high cyber
    elif max_keyword_weight >= 3.0:
        cap = "Medium"  # controlled substances
    elif max_keyword_weight >= 2.4:
        cap = "Low"  # cannabis family
    else:
        cap = "None"  # ops/ambiguous-only

    # Apply cap (min by severity)
    if _LEVEL_ORDER[level] > _LEVEL_ORDER[cap]:
        return cap
    return level


def compute_base_confidence(
    text: str,
    language: str,
    params: ScoringParams,
) -> Tuple[float, Dict[str, Set[str]], int, int, float]:
    """Return (base_confidence, iocs, ioc_hit_count, keyword_hit_count, max_keyword_weight)."""
    text = text or ""

    iocs = extract_iocs(text)
    ioc_raw, ioc_hits = ioc_score(iocs)

    tokens = tokenize(text)
    kw_raw, kw_hits, kw_hit_terms = keyword_score(text=text, language=language, tokens=tokens)

    # Determine the strongest matched keyword weight for level capping.
    lang = (language or "").strip().lower()
    max_kw_weight = 0.0
    for term in kw_hit_terms.keys():
        if term in UNIVERSAL_TOKEN_KEYWORDS.weights:
            max_kw_weight = max(max_kw_weight, float(UNIVERSAL_TOKEN_KEYWORDS.weights[term]))
        if term in UNIVERSAL_PHRASE_KEYWORDS.phrase_weights:
            max_kw_weight = max(max_kw_weight, float(UNIVERSAL_PHRASE_KEYWORDS.phrase_weights[term]))
        if lang in {"english", "en"} and term in EN_VIOLENCE_CYBER_KEYWORDS.weights:
            max_kw_weight = max(max_kw_weight, float(EN_VIOLENCE_CYBER_KEYWORDS.weights[term]))
        if lang in {"malay", "ms", "bahasa", "bahasa malay", "bahasa malaysia"} and term in MS_VIOLENCE_CYBER_KEYWORDS.weights:
            max_kw_weight = max(max_kw_weight, float(MS_VIOLENCE_CYBER_KEYWORDS.weights[term]))

    # Combine raw signals (IOC is typically stronger, so weight it up)
    raw = (2.0 * ioc_raw) + (1.0 * kw_raw)

    conf = raw_to_confidence(raw, params.raw_scale)

    if ioc_hits:
        conf *= 1.0 + params.ioc_multiplier_per_hit * ioc_hits
    if kw_hits:
        conf *= 1.0 + params.keyword_multiplier_per_hit * kw_hits

    # Keep in [0, 1]
    conf = max(0.0, min(conf, 1.0))
    return conf, iocs, ioc_hits, kw_hits, max_kw_weight


@dataclass(frozen=True)
class SingleTextThreatResult:
    author: str
    language: str
    base_confidence: float
    base_level: str
    iocs: Dict[str, Set[str]]
    ioc_hit_count: int
    keyword_hit_count: int
    max_keyword_weight: float


def label_single_text(
    *,
    author: str,
    text: str,
    language: str,
    params: ScoringParams | None = None,
) -> SingleTextThreatResult:
    """Label a single (author, text) input using the same dataset formulas."""
    p = params or ScoringParams()
    conf, iocs, ioc_hits, kw_hits, max_kw_w = compute_base_confidence(
        text=text,
        language=language,
        params=p,
    )
    level = confidence_to_level_capped(conf, max_kw_w)
    return SingleTextThreatResult(
        author=str(author or ""),
        language=str(language or ""),
        base_confidence=conf,
        base_level=level,
        iocs=iocs,
        ioc_hit_count=ioc_hits,
        keyword_hit_count=kw_hits,
        max_keyword_weight=max_kw_w,
    )


def apply_author_correlation(
    base_confs: Sequence[float],
    authors: Sequence[str],
    params: ScoringParams,
) -> Tuple[List[float], Mapping[str, int]]:
    # Count threat posts per author using base confidence (no author bias)
    threat_posts_by_author: Dict[str, int] = defaultdict(int)
    for author, conf in zip(authors, base_confs):
        if conf >= params.author_threat_conf_threshold:
            threat_posts_by_author[author] += 1

    final_confs: List[float] = []
    for author, conf in zip(authors, base_confs):
        n = threat_posts_by_author.get(author, 0)
        mult = 1.0 + min(params.author_multiplier_per_threat_post * n, params.author_multiplier_cap)
        final = max(0.0, min(conf * mult, 1.0))
        final_confs.append(final)

    return final_confs, threat_posts_by_author


# ----------------------------
# CSV IO
# ----------------------------

EXPECTED_COLS = ["Author", "Texts", "Language", "Threat_Confidence", "Threat_Level"]


def normalize_header(header: Sequence[str]) -> List[str]:
    return [h.strip() for h in header]


def label_dataset(
    input_csv: Path,
    output_csv: Path,
    params: ScoringParams,
    encoding: str = "utf-8",
) -> None:
    rows: List[Dict[str, str]] = []
    input_fieldnames: List[str] = []

    with input_csv.open("r", encoding=encoding, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("Input CSV has no header row")
        input_fieldnames = normalize_header(reader.fieldnames)
        header = input_fieldnames
        missing = [c for c in EXPECTED_COLS if c not in header]
        if missing:
            raise ValueError(f"Missing expected columns: {missing}. Found: {header}")

        for row in reader:
            # Preserve all original columns (even if extra)
            rows.append({k: (v if v is not None else "") for k, v in row.items()})

    authors = [r.get("Author", "") for r in rows]
    base_confs: List[float] = []
    max_kw_weights: List[float] = []

    for r in rows:
        conf, _, _, _, max_kw_w = compute_base_confidence(
            text=r.get("Texts", ""),
            language=r.get("Language", ""),
            params=params,
        )
        base_confs.append(conf)
        max_kw_weights.append(max_kw_w)

    final_confs, threat_posts_by_author = apply_author_correlation(base_confs, authors, params)

    for r, conf, max_kw_w in zip(rows, final_confs, max_kw_weights):
        r["Threat_Confidence"] = f"{conf:.4f}"
        r["Threat_Level"] = confidence_to_level_capped(conf, max_kw_w)

    # Write fully-quoted CSV for safety (commas/quotes/newlines in Texts)
    with output_csv.open("w", encoding=encoding, newline="") as f:
        # Preserve original column order; append any extra keys that appeared.
        fieldnames = list(input_fieldnames)
        for key in rows[0].keys() if rows else []:
            if key not in fieldnames:
                fieldnames.append(key)
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames if rows else EXPECTED_COLS,
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
        )
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

    # Lightweight summary
    levels = Counter(r["Threat_Level"] for r in rows)
    top_authors = Counter(threat_posts_by_author).most_common(10)

    print(f"Wrote: {output_csv}")
    print(f"Rows: {len(rows)}")
    print("Threat_Level counts:", dict(levels))
    if top_authors:
        print("Top authors by threat-post count (base_conf >= threshold):")
        for author, n in top_authors:
            print(f"  {author}: {n}")


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Label Threat_Confidence and Threat_Level in a CSV dataset")
    p.add_argument(
        "--input",
        default=str(Path("Dataset_CTI_DW") / "language_dataset_fixed.csv"),
        help="Input CSV path",
    )
    p.add_argument(
        "--output",
        default=str(Path("Dataset_CTI_DW") / "language_dataset_threat_labeled.csv"),
        help="Output CSV path (new file)",
    )
    p.add_argument("--raw-scale", type=float, default=10.0, help="Scale for raw->confidence mapping")
    p.add_argument("--ioc-mult", type=float, default=0.05, help="Confidence multiplier per IOC hit")
    p.add_argument("--kw-mult", type=float, default=0.03, help="Confidence multiplier per keyword hit")
    p.add_argument("--author-mult", type=float, default=0.02, help="Multiplier per author threat-post")
    p.add_argument("--author-cap", type=float, default=0.50, help="Max author multiplier (e.g., 0.50 = +50%)")
    p.add_argument(
        "--author-threshold",
        type=float,
        default=0.55,
        help="Base confidence threshold to count a row as an author threat-post",
    )
    p.add_argument("--encoding", default="utf-8", help="File encoding")
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    params = ScoringParams(
        raw_scale=args.raw_scale,
        ioc_multiplier_per_hit=args.ioc_mult,
        keyword_multiplier_per_hit=args.kw_mult,
        author_multiplier_per_threat_post=args.author_mult,
        author_multiplier_cap=args.author_cap,
        author_threat_conf_threshold=args.author_threshold,
    )

    input_csv = Path(args.input)
    output_csv = Path(args.output)

    if not input_csv.exists():
        raise FileNotFoundError(f"Input not found: {input_csv}")

    label_dataset(input_csv=input_csv, output_csv=output_csv, params=params, encoding=args.encoding)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
