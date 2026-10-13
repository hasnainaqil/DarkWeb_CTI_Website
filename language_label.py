"""Fill the Language column for merged_dataset.csv.

Rule (as requested):
- If any `malay_keywords` exists in the row's `Texts`, label as "Malay".
- Otherwise label as "English".

This script does NOT modify any existing CSV. It writes a new CSV:
`language_dataset.csv`.

Usage:
    python language_label.py
    python language_label.py --input merged_dataset.csv --output language_dataset.csv
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import shutil
from dataclasses import dataclass
from functools import lru_cache


# Some rows in the dataset can contain very large text fields.
# On Windows, setting to 2**31-1 avoids C long overflow.
csv.field_size_limit(2**31 - 1)


# ==============================
# 2. Define Malay keywords
# ==============================
malay_keywords = [
"ini", "itu", "ni", "ialah", "adalah", "dan", "yang", "untuk", "dengan", "juga", "tak", "tidak",
"boleh", "saya", "aku", "kami", "kita", "anda", "kau", "kenapa", "mengapa", "apa", "siapa", "mana",
"dari", "ke", "pada", "dalam", "sebagai", "kah", "pun", "nak", "dgn", "gila",
"lahh", "weh", "takde", "xde", "dah", "ya", "di", "yg",
"sbb", "tapi", "kepada", "kpd", "bukan", "utk", "ada",
"kot", "situ", "ko", "jer", "kalau", "sebab", "haah", "betul", "memang", "sudah",
"masih", "telah", "akan", "bkn", "terpaling", "kerajaan", "semua", "kes",
"tengok", "tgk", "tgok", "salah", "xtahu", "dh", "duit", "wang", "orang", "org", "mampu", "bagi",
"oleh", "makanan", "kena", "kene", "entah", "engkau", "minuman", "barang", "brg", "jual",
"beli", "jom", "tahu", "tau", "gini", "gitu", "besar", "kecil", "kecik", "bole", "lepas",
"lps", "nnt", "nnti", "mkn", "minum", "sekali", "skali", "secara", "dia", "diaorang", "dorang", "dorg",
"depa", "suka", "xsuka", "sgt", "sngt", "saja", "dulu", "dahulu", "sekarang", "skrg", "kejap",
"ja", "pernah", "cepat", "cpt", "lambat", "lmbt", "lama", "baru", "baharu", "sesuka",
"biar", "biarlah", "jangan", "jgn", "biarla", "knp", "dapat", "dpt",
"rakyat", "ikut", "ikutlah", "ikutkan", "kiri", "kanan", "atas", "bawah", "demi", "kata", "cakap", "ckp",
"beri", "merupakan", "mungkin", "penjarakan", "nak", "ada", "buat", "jaga", "pakai",
"lagi", "kat", "hari", "pkp", "ramai", "rumah", "raya", "amalkan", "macam", "kitajagakita",
"bila", "masa", "negeri", "kan", "mcm", "balik", "dekat", "perlu", "jadi", "keluar", "kerja",
"duduk", "masuk", "satu", "muka", "tempat", "lain", "sama", "pergi", "terus", "makan", "selamat",
"diri", "naik", "selangor", "sabah", "sampai", "tiada", "sendiri", "betul", "atau", "kedai",
"lupa", "tangan", "menteri", "pon", "pulak", "lebih", "dlm", "sangat",
"negara", "sentiasa", "pelitup", "rasa", "mereka", "kesihatan", "penyakit", "jangkitan",
"berada", "sekitar", "langkah", "pencegahan", "kawalan", "masyarakat", "keluarga", "anak", "ibu", "bapa",
"hidup", "mati", "panjang", "pendek", "awal", "akhir", "luar", "tepi", "tengah",
"ramadan", "puasa", "buka", "sahur", "doa", "rezeki", "berkat", "syukur", "sabar", "kuat", "lemah",
"senang", "susah", "kenyataan", "harapan", "impian", "usaha", "berjaya", "gagal", "pasti", "tentu",
"harap", "ingat", "tanya", "jawab", "faham", "kenal", "jumpa", "tinggal", "datang", "selalu",
"jarang", "kadang", "cegah", "rawat", "jauh", "rapat", "asing", "bersih", "kotor", "basuh",
"tutup", "elak", "kurang", "tambah", "cukup", "segera", "nanti", "esok", "semalam",
"ade", "korg", "kite", "kitorang", "diorang", "camtu", "camni", "cmni",
"cmtu", "camne", "camana", "cmne", "cmana", "gituu", "pastu",
"slps", "skang", "skrgni", "tdi", "mlm", "pgi", "ptg",
"ari", "hrini", "hrtu", "hrni", "smlm", "ari2", "kenape",
"jgk", "jerr", "lerr",
"meh", "meh2", "mehlah", "mehni", "woi",
"alahai", "adoi", "adoii", "ishh",
"amboi", "amboii", "fuh", "pergh", "peh", "padu", "mantap",
"cun", "cunlah", "cun2", "lawa", "hensem", "comel", "gebu",
"sempoi", "sempoii", "poyo", "gedik", "gedikk", "gediks",
"leceh", "renyah", "kecoh", "kecohh", "kecikk",
"besaq", "hang", "hampa", "sat", "satgi", "satgik", "satlagi",
"jap", "japgi", "kejapgi", "kejapp", "lamaa", "lame", "lamee",
"cepat2", "lambat2", "lajuu", "dahh", "dahla", "dahlaa",
"dahpun", "belom", "lom", "gi",
"balikk", "blk", "blkng", "blkang", "dpn", "blkg",
"sinih", "sinilah", "situlah", "sanalah",
"mane", "mne", "ktne", "ktmana", "katne",
"cana", "cne", "cmtu2",
"bgi", "bgilah", "bgitu",
"amik", "amikkk", "amiklah", "ambik", "ambiklah",
"letakk", "taruk", "tarok", "campak", "campakk",
"simpen", "bukak", "bukakk", "tutupk", "tutuplah",
"sebelum", "sblum", "pertama", "kedua", "ketiga", "celaka", "butoh", "8481",
"bodoh", "bangang", "bangsat", "babi", "anjing", "pukimak", "sial","bahlol",
"tahtah", "untuk", "bodohnya", "buat", "ni", "dan", "jom", "dan",
"sila", "bila", "dengan"
]


_WORD_RE = re.compile(r"\b\w+\b")


@dataclass(frozen=True)
class LabelDebug:
    label: str
    malay_hits: tuple[str, ...]
    malay_hit_count: int
    english_hit_count: int

_CLITIC_SUFFIXES: tuple[str, ...] = (
    "lah",
    "kah",
    "pun",
    "nya",
    "ku",
    "mu",
)

_PREFIX_STRIP: tuple[str, ...] = (
    "di",
    "ke",
    "se",
)


def _normalize_token(token: str) -> str:
    """Normalize a token for keyword matching.

    Handles common informal Malay patterns:
    - enclitic suffixes: -lah/-kah/-pun/-nya/-ku/-mu
    - reduplication shorthand: cepat2 -> cepat
    """
    token = (token or "").strip().lower()
    if not token:
        return ""

    # Strip reduplication shorthand (e.g., cepat2, ari2)
    if len(token) > 2 and token.endswith("2") and token[:-1].isalpha():
        token = token[:-1]

    # Strip common clitics repeatedly (bodohnya -> bodoh, ikutlah -> ikut)
    changed = True
    while changed:
        changed = False
        for suf in _CLITIC_SUFFIXES:
            if token.endswith(suf) and len(token) > len(suf) + 2:
                token = token[: -len(suf)]
                changed = True
                break

    return token


def _token_variants(token: str) -> tuple[str, ...]:
    """Return candidate variants for matching.

    Helps catch glued Malay/Indo prepositions like:
    - dirumah -> rumah
    - dikedai -> kedai
    - kesana -> sana
    """
    token = (token or "").strip().lower()
    if not token:
        return ()

    ntok = _normalize_token(token)
    variants: list[str] = [token]
    if ntok and ntok != token:
        variants.append(ntok)

    # Prefix stripping (only when the remaining part is non-trivial)
    for pref in _PREFIX_STRIP:
        for t in (token, ntok):
            if t.startswith(pref) and len(t) > len(pref) + 2:
                variants.append(t[len(pref) :])

    # Deduplicate while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return tuple(out)


def _build_keyword_set(keywords: list[str]) -> set[str]:
    """Normalize and deduplicate keywords for case-insensitive token matching."""
    out: set[str] = set()
    for kw in keywords:
        kw = (kw or "").strip().lower()
        if not kw:
            continue
        out.add(kw)
    return out


@lru_cache(maxsize=1)
def malay_keyword_set() -> set[str]:
    return _build_keyword_set(malay_keywords)


_ENGLISH_WORDS: set[str] = {
    "a",
    "about",
    "all",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "because",
    "but",
    "by",
    "can",
    "do",
    "don",
    "for",
    "from",
    "get",
    "had",
    "has",
    "have",
    "he",
    "her",
    "here",
    "him",
    "his",
    "how",
    "i",
    "if",
    "in",
    "into",
    "is",
    "it",
    "just",
    "like",
    "me",
    "more",
    "my",
    "no",
    "not",
    "of",
    "on",
    "one",
    "or",
    "our",
    "out",
    "people",
    "please",
    "really",
    "said",
    "say",
    "see",
    "she",
    "so",
    "some",
    "that",
    "the",
    "their",
    "them",
    "then",
    "there",
    "they",
    "this",
    "to",
    "too",
    "up",
    "us",
    "was",
    "we",
    "were",
    "what",
    "when",
    "where",
    "who",
    "why",
    "will",
    "with",
    "would",
    "you",
    "your",
}


_AMBIGUOUS_MALAY_TOKENS: set[str] = {
    "a",
    "ada",
    "akan",
    "apa",
    "dah",
    "dan",
    "di",
    "dia",
    "dgn",
    "ini",
    "itu",
    "je",
    "jg",
    "juga",
    "kan",
    "ke",
    "lagi",
    "lah",
    "nak",
    "ni",
    "nya",
    "ok",
    "pon",
    "pun",
    "saja",
    "tak",
    "tapi",
    "tu",
    "utk",
    "ya",
    "yang",
    "yg",
}


def _extract_debug(text: str, *, keywords: set[str]) -> LabelDebug:
    text = (text or "").strip()
    if not text:
        return LabelDebug(label="English", malay_hits=(), malay_hit_count=0, english_hit_count=0)

    tokens = _WORD_RE.findall(text.lower())
    malay_hits: set[str] = set()
    english_hit_count = 0

    for tok in tokens:
        if tok in _ENGLISH_WORDS:
            english_hit_count += 1

        for cand in _token_variants(tok):
            if cand in keywords:
                malay_hits.add(cand)
                break

    label = "Malay" if malay_hits else "English"
    return LabelDebug(
        label=label,
        malay_hits=tuple(sorted(malay_hits)),
        malay_hit_count=len(malay_hits),
        english_hit_count=english_hit_count,
    )


def label_language(text: str, *, keywords: set[str]) -> str:
    """Label language using word-by-word keyword presence.

    A text is "Malay" if ANY token (word) in the text matches ANY keyword in
    `malay_keywords`, ignoring case. Otherwise "English".
    """
    return _extract_debug(text, keywords=keywords).label


def label_language_hybrid(text: str, *, keywords: set[str]) -> str:
    """Hybrid labeling: keywords first, otherwise optional statistical LID.

    Behavior:
    - If Malay keyword hits exist -> Malay
    - Else, if `langid` is installed: classify; ms/id -> Malay, en -> English
    - Else -> English
    """
    # High-recall behavior:
    # 1) If ANY Malay keyword evidence exists -> Malay
    dbg = _extract_debug(text, keywords=keywords)
    if dbg.malay_hit_count:
        return "Malay"

    # 2) Otherwise fall back to statistical LID if available,
    # but only for sufficiently long texts.
    try:
        import langid  # type: ignore
    except Exception:
        return "English"

    t = (text or "").strip()
    if len(t) < 25:
        return "English"

    word_count = len(_WORD_RE.findall(t.lower()))
    if word_count < 5:
        return "English"

    lang, score = langid.classify(t)
    # langid returns a score (not a strict probability). Higher is "more confident".
    if lang in {"ms", "id"} and score >= 1.0:
        return "Malay"
    return "English"


def label_language_scored(text: str, *, keywords: set[str]) -> str:
    """Keyword scoring to reduce false positives on mixed English text.

    Heuristic intent: label the *dominant* language for noisy social text.
    - Prefer Malay when there is at least one non-ambiguous Malay hit.
    - Avoid labeling Malay when the only Malay evidence is a single very-ambiguous token
      (e.g., "kan", "di", "ya") and the text contains many English tokens.

    This is still heuristic (no ground truth), but it reduces obvious mismatches.
    """
    dbg = _extract_debug(text, keywords=keywords)
    if dbg.malay_hit_count == 0:
        return "English"

    tokens = _WORD_RE.findall(((text or "").lower()))
    token_count = len(tokens)

    strong_malay_hits = [h for h in dbg.malay_hits if h not in _AMBIGUOUS_MALAY_TOKENS and len(h) >= 3]
    if strong_malay_hits:
        return "Malay"

    # If only ambiguous evidence and English evidence is strong, prefer English.
    if dbg.malay_hit_count == 1 and dbg.english_hit_count >= 5:
        return "English"

    # For short texts, a couple of Malay hits is enough.
    if dbg.malay_hit_count >= 2 and token_count <= 20:
        return "Malay"

    # For longer texts, require more Malay evidence if we have lots of English tokens.
    if dbg.english_hit_count >= 8 and dbg.malay_hit_count < 3:
        return "English"

    return "Malay"


def label_language_with_debug(text: str, *, mode: str = "scored") -> LabelDebug:
    """Label a single input string and return lightweight debug information."""
    kw = malay_keyword_set()
    dbg = _extract_debug(text, keywords=kw)

    m = (mode or "scored").strip().lower()
    if m == "keyword":
        label = label_language(text, keywords=kw)
    elif m == "hybrid":
        label = label_language_hybrid(text, keywords=kw)
    elif m == "scored":
        label = label_language_scored(text, keywords=kw)
    else:
        raise ValueError("Unsupported mode. Use 'keyword', 'scored', or 'hybrid'.")

    return LabelDebug(
        label=label,
        malay_hits=dbg.malay_hits,
        malay_hit_count=dbg.malay_hit_count,
        english_hit_count=dbg.english_hit_count,
    )


def write_language_labeled_csv(
    input_path: str,
    output_path: str,
    *,
    texts_column: str = "Texts",
    language_column: str = "Language",
    mode: str = "keyword",
) -> tuple[int, int]:
    """Return (rows_in, rows_out)."""
    keyword_set = _build_keyword_set(malay_keywords)
    rows_in = 0
    rows_out = 0

    mode = (mode or "keyword").strip().lower()
    if mode not in {"keyword", "scored", "hybrid"}:
        raise ValueError(f"Unsupported mode: {mode}. Use 'keyword', 'scored', or 'hybrid'.")

    def _parse_known_5col_line(line: str) -> list[str] | None:
        """Parse a row for the known 5-column schema.

        Expected order: Author, Texts, Language, Threat_Confidence, Threat_Level

        This parser is resilient to:
        - unquoted commas inside Texts
        - stray double-quotes inside Texts (which break csv.reader)
        It does NOT support embedded newlines inside a single record.
        """
        line = (line or "").rstrip("\r\n")
        # Some rows contain stray carriage returns inside the text payload.
        # Replace them so we don't accidentally treat embedded CSV-looking
        # fragments as part of trailing columns.
        if "\r" in line:
            line = line.replace("\r", " ")
        if not line:
            return None
        if "," not in line:
            return None
        author, rest = line.split(",", 1)
        parts = rest.rsplit(",", 3)
        if len(parts) == 4:
            texts, language, threat_conf, threat_level = parts
        else:
            # If missing trailing columns, pad them.
            padded = parts + [""] * (4 - len(parts))
            texts, language, threat_conf, threat_level = padded[:4]
        return [author, texts, language, threat_conf, threat_level]

    with open(input_path, "r", encoding="utf-8", errors="replace") as f_in:
        header_line = f_in.readline()
        if not header_line:
            raise ValueError("Input CSV is empty")
        fieldnames = [h.strip() for h in header_line.rstrip("\r\n").split(",")]
        if not fieldnames:
            raise ValueError("Input CSV has no header")

        missing = [c for c in [texts_column, language_column] if c not in fieldnames]
        if missing:
            raise ValueError(
                f"Input CSV missing required columns: {missing}. Found columns: {fieldnames}"
            )

        # Only supported schema for robust parsing.
        expected = ["Author", "Texts", "Language", "Threat_Confidence", "Threat_Level"]
        if fieldnames != expected:
            raise ValueError(
                "Unsupported input header for robust parsing. "
                f"Expected {expected} but got {fieldnames}"
            )

        texts_idx = 1
        language_idx = 2

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        tmp_output = output_path + ".tmp"
        try:
            with open(tmp_output, "w", newline="", encoding="utf-8") as f_out:
                writer = csv.writer(f_out, quoting=csv.QUOTE_ALL)
                writer.writerow(fieldnames)

                for line in f_in:
                    parsed = _parse_known_5col_line(line)
                    if parsed is None:
                        continue
                    rows_in += 1
                    text = parsed[texts_idx]

                    if mode == "hybrid":
                        parsed[language_idx] = label_language_hybrid(text, keywords=keyword_set)
                    elif mode == "scored":
                        parsed[language_idx] = label_language_scored(text, keywords=keyword_set)
                    else:
                        parsed[language_idx] = label_language(text, keywords=keyword_set)

                    writer.writerow(parsed)
                    rows_out += 1

            try:
                os.replace(tmp_output, output_path)
            except PermissionError:
                # If the destination is temporarily locked (e.g., OneDrive/Excel),
                # fall back to copy-over.
                with open(tmp_output, "rb") as src, open(output_path, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                try:
                    os.remove(tmp_output)
                except OSError:
                    pass
        finally:
            # Best-effort cleanup if something fails mid-way.
            if os.path.exists(tmp_output):
                try:
                    os.remove(tmp_output)
                except OSError:
                    pass

    return rows_in, rows_out


def audit_language_dataset(
    labeled_csv_path: str,
    report_path: str,
    *,
    texts_column: str = "Texts",
    language_column: str = "Language",
    author_column: str = "Author",
    max_rows: int | None = None,
    enable_langid: bool = True,
) -> dict[str, int]:
    """Create a CSV report of suspicious rows and return summary counters."""
    keyword_set = _build_keyword_set(malay_keywords)

    classify_langid = None
    if enable_langid:
        try:
            import langid  # type: ignore

            classify_langid = langid.classify
        except Exception:
            classify_langid = None

    os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
    tmp_output = report_path + ".tmp"

    counters = {
        "rows": 0,
        "suspicious": 0,
        "english_labeled_but_malay_hits": 0,
        "malay_labeled_but_only_ambiguous_hit": 0,
        "english_labeled_but_langid_ms_id": 0,
    }

    with open(labeled_csv_path, "r", newline="", encoding="utf-8", errors="replace") as f_in:
        reader = csv.reader(f_in)
        try:
            fieldnames = next(reader)
        except StopIteration:
            raise ValueError("Input CSV is empty")
        if not fieldnames:
            raise ValueError("Input CSV has no header")

        missing = [c for c in [texts_column, language_column] if c not in fieldnames]
        if missing:
            raise ValueError(
                f"Input CSV missing required columns: {missing}. Found columns: {fieldnames}"
            )

        try:
            texts_idx = fieldnames.index(texts_column)
            language_idx = fieldnames.index(language_column)
            author_idx = fieldnames.index(author_column) if author_column in fieldnames else None
        except ValueError:
            texts_idx = 1
            language_idx = 2
            author_idx = 0

        report_fields = [
            "Reason",
            author_column,
            language_column,
            "MalayHitCount",
            "EnglishHitCount",
            "MalayHits",
            texts_column,
        ]

        with open(tmp_output, "w", newline="", encoding="utf-8") as f_out:
            writer = csv.DictWriter(f_out, fieldnames=report_fields)
            writer.writeheader()

            for row in reader:
                counters["rows"] += 1
                if max_rows is not None and counters["rows"] > max_rows:
                    break

                if len(row) < len(fieldnames):
                    row = row + [""] * (len(fieldnames) - len(row))
                elif len(row) > len(fieldnames):
                    row = row[: len(fieldnames)]

                text = row[texts_idx] if texts_idx < len(row) else ""
                gold_label = (row[language_idx] if language_idx < len(row) else "").strip()
                author_val = (
                    row[author_idx] if (author_idx is not None and author_idx < len(row)) else ""
                )
                dbg = _extract_debug(text, keywords=keyword_set)

                # Heuristic flags (NOT ground truth):
                # 1) Labeled English but Malay keyword evidence is strong.
                if gold_label.lower() == "english" and dbg.malay_hit_count >= 2:
                    counters["suspicious"] += 1
                    counters["english_labeled_but_malay_hits"] += 1
                    writer.writerow(
                        {
                            "Reason": "English label but >=2 Malay keyword hits",
                            author_column: author_val,
                            language_column: gold_label,
                            "MalayHitCount": dbg.malay_hit_count,
                            "EnglishHitCount": dbg.english_hit_count,
                            "MalayHits": " ".join(dbg.malay_hits),
                            texts_column: text,
                        }
                    )
                    continue

                # 1b) Labeled English but langid predicts Malay/Indonesian.
                if classify_langid is not None and gold_label.lower() == "english":
                    t = (text or "").strip()
                    if t:
                        try:
                            lang, prob = classify_langid(t)
                        except Exception:
                            lang, prob = "", 0.0
                        if lang in {"ms", "id"} and prob >= 1.0:
                            counters["suspicious"] += 1
                            counters["english_labeled_but_langid_ms_id"] += 1
                            writer.writerow(
                                {
                                    "Reason": f"English label but langid={lang} (p={prob:.2f})",
                                    author_column: author_val,
                                    language_column: gold_label,
                                    "MalayHitCount": dbg.malay_hit_count,
                                    "EnglishHitCount": dbg.english_hit_count,
                                    "MalayHits": " ".join(dbg.malay_hits),
                                    texts_column: text,
                                }
                            )
                            continue

                # 2) Labeled Malay but only a single very-ambiguous Malay hit and many English words.
                if (
                    gold_label.lower() == "malay"
                    and dbg.malay_hit_count == 1
                    and dbg.malay_hits
                    and dbg.malay_hits[0] in _AMBIGUOUS_MALAY_TOKENS
                    and dbg.english_hit_count >= 5
                ):
                    counters["suspicious"] += 1
                    counters["malay_labeled_but_only_ambiguous_hit"] += 1
                    writer.writerow(
                        {
                            "Reason": "Malay label but only ambiguous Malay hit + many English words",
                            author_column: author_val,
                            language_column: gold_label,
                            "MalayHitCount": dbg.malay_hit_count,
                            "EnglishHitCount": dbg.english_hit_count,
                            "MalayHits": " ".join(dbg.malay_hits),
                            texts_column: text,
                        }
                    )

    try:
        os.replace(tmp_output, report_path)
    except PermissionError:
        with open(tmp_output, "rb") as src, open(report_path, "wb") as dst:
            shutil.copyfileobj(src, dst)
        os.remove(tmp_output)
    finally:
        if os.path.exists(tmp_output):
            try:
                os.remove(tmp_output)
            except OSError:
                pass

    return counters


def main(argv: list[str] | None = None) -> int:
    default_input = os.path.join(os.path.dirname(__file__), "merged_dataset.csv")
    default_output = os.path.join(os.path.dirname(__file__), "language_dataset.csv")
    default_audit_in = default_output
    default_audit_out = os.path.join(os.path.dirname(__file__), "language_audit.csv")

    parser = argparse.ArgumentParser(
        description='Fill the Language column as "Malay" if malay_keywords appear in Texts; else "English".'
    )
    parser.add_argument("--input", default=default_input, help="Input CSV path (default: merged_dataset.csv)")
    parser.add_argument(
        "--output",
        default=default_output,
        help="Output CSV path (default: language_dataset.csv)",
    )
    parser.add_argument(
        "--mode",
        default="keyword",
        choices=["keyword", "scored", "hybrid"],
        help="Labeling mode: keyword (any hit), scored (majority-leaning), or hybrid (scored + optional langid)",
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Audit an already-labeled CSV and write a suspicious-rows report",
    )
    parser.add_argument(
        "--audit-input",
        default=default_audit_in,
        help="Audit input CSV path (default: language_dataset.csv)",
    )
    parser.add_argument(
        "--audit-output",
        default=default_audit_out,
        help="Audit report CSV path (default: language_audit.csv)",
    )
    parser.add_argument(
        "--audit-max-rows",
        type=int,
        default=0,
        help="Audit at most N rows (0 = all rows)",
    )
    args = parser.parse_args(argv)

    if args.audit:
        max_rows = None if args.audit_max_rows == 0 else args.audit_max_rows
        counters = audit_language_dataset(args.audit_input, args.audit_output, max_rows=max_rows)
        print(f"Audited: {counters['rows']} rows")
        print(f"Suspicious: {counters['suspicious']}")
        print(f"Report: {args.audit_output}")
        return 0

    rows_in, rows_out = write_language_labeled_csv(args.input, args.output, mode=args.mode)
    print(f"Wrote: {rows_out} rows (read {rows_in})")
    print(f"Mode: {args.mode}")
    print(f"Output: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())