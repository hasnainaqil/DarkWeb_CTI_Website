from __future__ import annotations

import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import networkx as nx
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from language_label import label_language_with_debug
from threat_labeler_standalone import (
    ScoringParams,
    confidence_to_level,
    confidence_to_level_capped,
    extract_iocs,
    ioc_score,
    keyword_score,
    label_single_text,
    raw_to_confidence,
    tokenize,
)

try:
    import psycopg2
    from psycopg2 import sql
except ModuleNotFoundError:
    psycopg2 = None
    sql = None


@dataclass(frozen=True)
class DataSource:
    kind: str  # "postgres"
    details: str


DEFAULT_TABLE = os.getenv("DWCTI_TABLE", 'public."DarkWeb_CTI_Data"')


_CYBER_UI_CSS = """
<style>
    /*
        UI theme rules:
        - No hard-coded colors: we only use Streamlit theme CSS variables.
        - Purely presentational; no data/logic changes.
    */

    :root {
        --dwcti-accent: var(--primary-color);
        --dwcti-border: color-mix(in srgb, var(--text-color) 14%, transparent);
        --dwcti-muted-border: color-mix(in srgb, var(--text-color) 10%, transparent);
        --dwcti-glow: color-mix(in srgb, var(--primary-color) 26%, transparent);
        --dwcti-glow-strong: color-mix(in srgb, var(--primary-color) 38%, transparent);
        --dwcti-panel-a: color-mix(in srgb, var(--secondary-background-color) 92%, transparent);
        --dwcti-panel-b: color-mix(in srgb, var(--background-color) 100%, transparent);
    }

    /* Cyber grid + subtle scanlines background */
    .stApp,
    [data-testid="stAppViewContainer"] {
        position: relative;
        /* Fallback (no color-mix): still shows obvious CTI glow */
        background:
            radial-gradient(circle at 18% 10%, var(--dwcti-accent) 0%, transparent 48%),
            radial-gradient(circle at 85% 0%, var(--dwcti-accent) 0%, transparent 46%),
            radial-gradient(circle at 65% 70%, var(--dwcti-accent) 0%, transparent 58%),
            linear-gradient(180deg, var(--background-color) 0%, var(--background-color) 100%);
        background-size: 160% 160%, 150% 150%, 170% 170%, 100% 100%;
        background-position: 0% 0%, 100% 0%, 40% 90%, 0% 0%;
        background-attachment: fixed;
        animation: dwcti-ambient 18s ease-in-out infinite;
    }

    /* Enhanced (color-mix): softer and more nuanced */
    @supports (color: color-mix(in srgb, white 50%, transparent)) {
        .stApp,
        [data-testid="stAppViewContainer"] {
            background:
                radial-gradient(
                    circle at 18% 10%,
                    color-mix(in srgb, var(--dwcti-accent) 14%, transparent) 0%,
                    transparent 45%
                ),
                radial-gradient(
                    circle at 85% 0%,
                    color-mix(in srgb, var(--dwcti-accent) 10%, transparent) 0%,
                    transparent 40%
                ),
                radial-gradient(
                    circle at 65% 70%,
                    color-mix(in srgb, var(--dwcti-accent) 8%, transparent) 0%,
                    transparent 52%
                ),
                linear-gradient(180deg, var(--background-color) 0%, var(--background-color) 100%);
        }
    }

    .stApp::before,
    [data-testid="stAppViewContainer"]::before {
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        z-index: 0;
        /* Fallback (no color-mix) */
        background-image:
            repeating-linear-gradient(0deg, var(--text-color) 0 1px, transparent 1px 24px),
            repeating-linear-gradient(90deg, var(--text-color) 0 1px, transparent 1px 24px),
            repeating-linear-gradient(180deg, transparent 0 10px, var(--text-color) 10px 11px),
            linear-gradient(90deg, transparent 0%, var(--dwcti-accent) 50%, transparent 100%);
        background-size: auto, auto, auto, 220% 100%;
        background-position: 0 0, 0 0, 0 0, -120% 0;
        opacity: 0.42;
        animation: dwcti-grid-drift 26s linear infinite, dwcti-sweep 9s ease-in-out infinite;
    }

    @supports (color: color-mix(in srgb, white 50%, transparent)) {
        .stApp::before,
        [data-testid="stAppViewContainer"]::before {
            background-image:
                repeating-linear-gradient(
                    0deg,
                    color-mix(in srgb, var(--text-color) 5%, transparent) 0 1px,
                    transparent 1px 24px
                ),
                repeating-linear-gradient(
                    90deg,
                    color-mix(in srgb, var(--text-color) 5%, transparent) 0 1px,
                    transparent 1px 24px
                ),
                repeating-linear-gradient(
                    180deg,
                    transparent 0 10px,
                    color-mix(in srgb, var(--text-color) 3%, transparent) 10px 11px
                ),
                linear-gradient(
                    90deg,
                    transparent 0%,
                    color-mix(in srgb, var(--dwcti-accent) 10%, transparent) 50%,
                    transparent 100%
                );
        }
    }

    /* Low-contrast watermark text (CTI vibe) */
    .stApp::after,
    [data-testid="stAppViewContainer"]::after {
        content: "THREAT INTELLIGENCE • IOC • TTP • DARK WEB";
        position: fixed;
        left: 2.5vw;
        bottom: 2.25vh;
        pointer-events: none;
        z-index: 0;
        font-weight: 700;
        letter-spacing: 0.22em;
        text-transform: uppercase;
        font-size: clamp(14px, 1.5vw, 20px);
        color: var(--text-color);
        opacity: 0.65;
        animation: dwcti-watermark-float 16s ease-in-out infinite;
    }

    @keyframes dwcti-ambient {
        0%   { background-position: 0% 0%, 100% 0%, 40% 90%, 0% 0%; }
        50%  { background-position: 18% 10%, 78% 12%, 55% 76%, 0% 0%; }
        100% { background-position: 0% 0%, 100% 0%, 40% 90%, 0% 0%; }
    }

    @keyframes dwcti-grid-drift {
        0%   { background-position: 0 0, 0 0, 0 0, -120% 0; }
        100% { background-position: 0 96px, 96px 0, 0 36px, 120% 0; }
    }

    @keyframes dwcti-sweep {
        0%   { opacity: 0.38; }
        50%  { opacity: 0.52; }
        100% { opacity: 0.38; }
    }

    @keyframes dwcti-watermark-float {
        0%   { transform: translateY(0); filter: drop-shadow(0 0 0 transparent); }
        50%  { transform: translateY(-6px); filter: drop-shadow(0 0 12px var(--dwcti-glow)); }
        100% { transform: translateY(0); filter: drop-shadow(0 0 0 transparent); }
    }

    @media (prefers-reduced-motion: reduce) {
        .stApp,
        .stApp::before,
        .stApp::after,
        [data-testid="stAppViewContainer"],
        [data-testid="stAppViewContainer"]::before,
        [data-testid="stAppViewContainer"]::after {
            animation: none !important;
        }
    }

    /* Keep main content above the background overlay */
    .stApp > header,
    .stApp > div,
    [data-testid="stAppViewContainer"] > header,
    [data-testid="stAppViewContainer"] > div {
        position: relative;
        z-index: 1;
    }

    /* Sidebar: soft gradient for depth */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, var(--secondary-background-color), var(--background-color));
        border-right: 1px solid var(--dwcti-muted-border);
        height: 100vh;
    }

    /* Fix: ensure the sidebar can scroll when content is long */
    [data-testid="stSidebar"] > div {
        height: 100vh;
        overflow-y: auto;
        overflow-x: hidden;
        padding-bottom: 2.5rem;
    }

    /* Headings: more console/HUD feel */
    h1, h2, h3 {
        letter-spacing: 0.35px;
    }

    h2, h3 {
        text-transform: uppercase;
    }

    /* Sidebar headings and expander headers: add an accent rule */
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] h2 {
        position: relative;
    }
    [data-testid="stSidebar"] h3::after,
    [data-testid="stSidebar"] h2::after {
        content: "";
        display: block;
        height: 2px;
        margin-top: 0.35rem;
        width: 100%;
        background: linear-gradient(
            90deg,
            color-mix(in srgb, var(--dwcti-accent) 55%, transparent),
            transparent
        );
        opacity: 0.9;
    }

    /* Cards (Streamlit bordered containers) */
    div[data-testid="stVerticalBlockBorderWrapper"] {
        position: relative;
        border-radius: 16px;
        border-color: var(--dwcti-border);
        background:
            linear-gradient(135deg, var(--dwcti-panel-a), var(--dwcti-panel-b)),
            repeating-linear-gradient(
                135deg,
                color-mix(in srgb, var(--dwcti-accent) 10%, transparent) 0 10px,
                transparent 10px 22px
            );
        box-shadow:
            0 0 0 1px color-mix(in srgb, var(--dwcti-accent) 20%, transparent) inset,
            0 0 22px var(--dwcti-glow);
    }

    /* Corner brackets (HUD panel look) */
    div[data-testid="stVerticalBlockBorderWrapper"]::before {
        content: "";
        position: absolute;
        inset: 10px;
        pointer-events: none;
        opacity: 0.9;
        background:
            linear-gradient(var(--dwcti-accent), var(--dwcti-accent)) left top / 18px 2px no-repeat,
            linear-gradient(var(--dwcti-accent), var(--dwcti-accent)) left top / 2px 18px no-repeat,
            linear-gradient(var(--dwcti-accent), var(--dwcti-accent)) right top / 18px 2px no-repeat,
            linear-gradient(var(--dwcti-accent), var(--dwcti-accent)) right top / 2px 18px no-repeat,
            linear-gradient(var(--dwcti-accent), var(--dwcti-accent)) left bottom / 18px 2px no-repeat,
            linear-gradient(var(--dwcti-accent), var(--dwcti-accent)) left bottom / 2px 18px no-repeat,
            linear-gradient(var(--dwcti-accent), var(--dwcti-accent)) right bottom / 18px 2px no-repeat,
            linear-gradient(var(--dwcti-accent), var(--dwcti-accent)) right bottom / 2px 18px no-repeat;
        filter: drop-shadow(0 0 8px var(--dwcti-glow-strong));
    }

    div[data-testid="stVerticalBlockBorderWrapper"] > div {
        padding: 0.95rem 1.05rem;
    }

    /* Hero header */
    .dwcti-hero {
        padding: 1.05rem 1.2rem;
        border-radius: 18px;
        border: 1px solid var(--dwcti-border);
        background:
            linear-gradient(
                135deg,
                var(--dwcti-panel-a),
                var(--dwcti-panel-b)
            );
        position: relative;
        overflow: hidden;
        box-shadow:
            0 0 0 1px color-mix(in srgb, var(--dwcti-accent) 26%, transparent) inset,
            0 0 30px var(--dwcti-glow-strong);
    }

    .dwcti-hero::after {
        content: "";
        position: absolute;
        inset: -55% -30% -55% -30%;
        background: repeating-linear-gradient(
            135deg,
            color-mix(in srgb, var(--dwcti-accent) 14%, transparent) 0 10px,
            transparent 10px 22px
        );
        transform: rotate(8deg);
        opacity: 0.55;
        pointer-events: none;
    }

    .dwcti-hero > * {
        position: relative;
    }

    .dwcti-hero-row {
        display: flex;
        gap: 1rem;
        align-items: center;
        justify-content: space-between;
        flex-wrap: wrap;
    }

    .dwcti-title {
        font-size: 1.65rem;
        font-weight: 700;
        letter-spacing: 0.2px;
        text-transform: uppercase;
    }

    .dwcti-title-wrap {
        display: flex;
        gap: 0.75rem;
        align-items: center;
    }

    .dwcti-mark {
        width: 34px;
        height: 34px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        border-radius: 12px;
        border: 1px solid color-mix(in srgb, var(--dwcti-accent) 45%, transparent);
        background: color-mix(in srgb, var(--secondary-background-color) 85%, transparent);
        box-shadow: 0 0 18px var(--dwcti-glow);
    }

    .dwcti-icon {
        width: 1.15em;
        height: 1.15em;
        vertical-align: -0.18em;
        margin-right: 0.35rem;
        fill: currentColor;
        opacity: 0.92;
        filter: drop-shadow(0 0 8px var(--dwcti-glow));
    }

    .dwcti-mark svg {
        width: 22px;
        height: 22px;
        fill: currentColor;
        opacity: 0.95;
    }

    .dwcti-subtitle {
        opacity: 0.88;
        margin-top: 0.25rem;
    }

    .dwcti-badges {
        display: flex;
        gap: 0.5rem;
        flex-wrap: wrap;
    }

    .dwcti-badge {
        padding: 0.35rem 0.6rem;
        border-radius: 999px;
        border: 1px solid var(--dwcti-muted-border);
        background: color-mix(in srgb, var(--secondary-background-color) 86%, transparent);
        font-size: 0.85rem;
        opacity: 0.95;
        white-space: nowrap;
    }

    .dwcti-badge--accent {
        border-color: color-mix(in srgb, var(--dwcti-accent) 55%, transparent);
        box-shadow: 0 0 16px var(--dwcti-glow);
    }

    /* Tabs: clearer separation */
    div[data-testid="stTabs"] button[role="tab"] {
        border-radius: 999px;
        padding: 0.4rem 0.8rem;
        border: 1px solid transparent;
    }

    div[data-testid="stTabs"] button[aria-selected="true"] {
        border: 1px solid color-mix(in srgb, var(--dwcti-accent) 70%, transparent);
        background: color-mix(in srgb, var(--dwcti-accent) 14%, var(--secondary-background-color) 86%);
        box-shadow: 0 0 16px var(--dwcti-glow);
    }

    /* Metrics: make them look like small HUD readouts */
    [data-testid="stMetric"] {
        padding: 0.55rem 0.75rem;
        border-radius: 14px;
        border: 1px solid var(--dwcti-muted-border);
        background: linear-gradient(135deg, var(--dwcti-panel-a), var(--dwcti-panel-b));
        box-shadow: 0 0 14px color-mix(in srgb, var(--dwcti-accent) 16%, transparent);
    }

    [data-testid="stMetric"] [data-testid="stMetricLabel"] {
        text-transform: uppercase;
        letter-spacing: 0.4px;
        opacity: 0.92;
    }

    /* Buttons: stronger outline + glow on hover */
    .stButton > button {
        border-radius: 999px;
        border: 1px solid color-mix(in srgb, var(--dwcti-accent) 45%, transparent);
        background: color-mix(in srgb, var(--secondary-background-color) 88%, transparent);
    }

    .stButton > button:hover {
        box-shadow: 0 0 18px var(--dwcti-glow);
        border-color: color-mix(in srgb, var(--dwcti-accent) 70%, transparent);
    }

    /* Dataframes: give breathing room */
    div[data-testid="stDataFrame"] {
        border-radius: 14px;
        overflow: hidden;
        border: 1px solid var(--dwcti-muted-border);
        box-shadow: 0 0 18px color-mix(in srgb, var(--dwcti-accent) 12%, transparent);
    }

    /* Code blocks: look like console panels */
    pre {
        border-radius: 14px;
        border: 1px solid var(--dwcti-muted-border) !important;
        box-shadow: 0 0 16px color-mix(in srgb, var(--dwcti-accent) 10%, transparent);
    }
</style>
"""


def _inject_cyber_ui() -> None:
    st.markdown(_CYBER_UI_CSS, unsafe_allow_html=True)


def _safe_db_id() -> str:
    url = os.getenv("DATABASE_URL")
    if url:
        p = urlparse(url)
        user = p.username or ""
        host = p.hostname or ""
        port = p.port or ""
        db = (p.path or "").lstrip("/")
        return f"url://{user}@{host}:{port}/{db}"

    host = os.getenv("PGHOST", "")
    port = os.getenv("PGPORT", "")
    database = os.getenv("PGDATABASE", "")
    user = os.getenv("PGUSER", "")
    sslmode = os.getenv("PGSSLMODE", "")
    return f"env://{user}@{host}:{port}/{database}?sslmode={sslmode}"


@st.cache_data(ttl=300, show_spinner="Loading data from Postgres...")
def _load_df_cached(db_id: str, table: str) -> pd.DataFrame:
    df, _ = load_from_postgres(table)
    return df


def _connect_postgres():
    if psycopg2 is None:
        raise RuntimeError("Missing dependency 'psycopg2'. Install psycopg2-binary.")

    url = os.getenv("DATABASE_URL")
    if url:
        return psycopg2.connect(url)

    # Project defaults: Supabase Session Pooler (IPv4 compatible)
    host = os.getenv("PGHOST", "aws-1-ap-northeast-2.pooler.supabase.com")
    port = int(os.getenv("PGPORT", "5432"))
    database = os.getenv("PGDATABASE", "postgres")
    user = os.getenv("PGUSER", "postgres.ypefuoljwvczzmivbgmb")
    password = os.getenv("PGPASSWORD")
    sslmode = os.getenv("PGSSLMODE", "require")
    hostaddr = os.getenv("PGHOSTADDR")

    if not host or not password:
        raise RuntimeError(
            "Missing connection env vars. Set DATABASE_URL or at least PGHOST and PGPASSWORD "
            "(also PGPORT/PGDATABASE/PGUSER as needed)."
        )

    kwargs = {
        "host": host,
        "port": port,
        "dbname": database,
        "user": user,
        "password": password,
        "sslmode": sslmode,
    }
    if hostaddr:
        kwargs["hostaddr"] = hostaddr

    return psycopg2.connect(**kwargs)


def load_from_postgres(table: str) -> Tuple[pd.DataFrame, DataSource]:
    conn = _connect_postgres()
    try:
        schema, table_name = _parse_schema_table(table)
        query = sql.SQL("SELECT * FROM {}.{};").format(
            sql.Identifier(schema),
            sql.Identifier(table_name),
        )
        df = pd.read_sql_query(query.as_string(conn), conn)
    finally:
        conn.close()

    return df, DataSource("postgres", f"{table}")


def insert_into_postgres(table: str, values: Dict[str, object]) -> None:
    conn = _connect_postgres()
    try:
        schema, table_name = _parse_schema_table(table)
        cols = list(values.keys())
        query = sql.SQL("INSERT INTO {}.{} ({}) VALUES ({})").format(
            sql.Identifier(schema),
            sql.Identifier(table_name),
            sql.SQL(", ").join(sql.Identifier(c) for c in cols),
            sql.SQL(", ").join(sql.Placeholder() for _ in cols),
        )
        with conn.cursor() as cur:
            cur.execute(query, [values[c] for c in cols])
        conn.commit()
    finally:
        conn.close()


def _parse_schema_table(value: str) -> Tuple[str, str]:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("Table name is empty")

    if "." in raw:
        schema, table = raw.split(".", 1)
    else:
        schema, table = "public", raw

    schema = schema.strip().strip('"')
    table = table.strip().strip('"')

    if not schema or not table:
        raise ValueError(f"Invalid table identifier: {value!r}")

    return schema, table


def coerce_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # Normalize expected column names if present
    rename = {}
    for col in df.columns:
        if col.lower() == "threat_confidence":
            rename[col] = "Threat_Confidence"
        elif col.lower() == "threat_level":
            rename[col] = "Threat_Level"
        elif col.lower() == "language":
            rename[col] = "Language"
        elif col.lower() == "author":
            rename[col] = "Author"
        elif col.lower() == "texts":
            rename[col] = "Texts"

    if rename:
        df = df.rename(columns=rename)

    # Try to parse threat confidence as numeric (but keep originals if conversion fails)
    if "Threat_Confidence" in df.columns:
        df["Threat_Confidence"] = pd.to_numeric(df["Threat_Confidence"], errors="coerce")

    for c in ["Author", "Language", "Threat_Level"]:
        if c in df.columns:
            df[c] = df[c].astype(str)

    return df


def _clamp01(v: float) -> float:
    return max(0.0, min(float(v), 1.0))


def author_correlation_adjustment(
    df: pd.DataFrame,
    *,
    author: str,
    base_confidence: float,
) -> Tuple[float, float, float, int]:
    """Return (final_confidence, alpha, author_prior_confidence, author_rows_used)."""
    if "Author" not in df.columns or "Threat_Confidence" not in df.columns:
        return _clamp01(base_confidence), 0.0, 0.0, 0

    a = (author or "").strip().lower()
    if not a:
        return _clamp01(base_confidence), 0.0, 0.0, 0

    authors = df["Author"].astype(str).str.strip().str.lower()
    same_author = df.loc[authors == a]
    if same_author.empty:
        return _clamp01(base_confidence), 0.0, 0.0, 0

    conf_series = pd.to_numeric(same_author["Threat_Confidence"], errors="coerce").dropna()
    if conf_series.empty:
        return _clamp01(base_confidence), 0.0, 0.0, 0

    author_rows = int(conf_series.shape[0])
    author_avg = float(conf_series.mean())
    author_max = float(conf_series.max())
    author_prior = _clamp01(max(author_avg, 0.9 * author_max))

    alpha = min(0.65, 0.25 + 0.10 * math.log1p(author_rows))
    final_conf = _clamp01((1.0 - alpha) * float(base_confidence) + alpha * author_prior)
    return final_conf, float(alpha), author_prior, author_rows


def _resolve_insert_columns(db_columns: list[str]) -> Dict[str, str]:
    """Map canonical column names to actual DB column names (case-insensitive)."""
    wanted = ["Author", "Texts", "Language", "Threat_Confidence", "Threat_Level"]
    cols_lower = {c.lower(): c for c in db_columns}
    mapping: Dict[str, str] = {}
    for w in wanted:
        if w in db_columns:
            mapping[w] = w
            continue
        hit = cols_lower.get(w.lower())
        if hit:
            mapping[w] = hit
    return mapping


def build_relationship_graph(df: pd.DataFrame, max_authors: int = 30) -> nx.Graph:
    g = nx.Graph()

    if not {"Author", "Language", "Threat_Level"}.issubset(df.columns):
        return g

    top_authors = (
        df["Author"].value_counts(dropna=False).head(max_authors).index.astype(str).tolist()
    )

    def node(name: str, kind: str) -> str:
        return f"{kind}:{name}"

    for _, row in df.iterrows():
        author = str(row.get("Author", ""))
        if author not in top_authors:
            continue

        language = str(row.get("Language", ""))
        threat = str(row.get("Threat_Level", ""))

        a = node(author, "author")
        l = node(language, "lang")
        t = node(threat, "threat")

        g.add_node(a, kind="author", label=author)
        g.add_node(l, kind="lang", label=language)
        g.add_node(t, kind="threat", label=threat)

        for u, v in [(a, l), (a, t), (l, t)]:
            if g.has_edge(u, v):
                g[u][v]["weight"] += 1
            else:
                g.add_edge(u, v, weight=1)

    return g


@st.cache_data(ttl=300, show_spinner="Extracting IOCs from texts...")
def build_ioc_tables(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    if "Texts" not in df.columns:
        empty = pd.DataFrame()
        return empty, empty

    rows = df.copy()
    if "Threat_Confidence" in rows.columns:
        rows["Threat_Confidence"] = pd.to_numeric(rows["Threat_Confidence"], errors="coerce")

    details: list[dict] = []
    for idx, r in rows.iterrows():
        text = str(r.get("Texts", "") or "")
        iocs = extract_iocs(text)
        if not iocs:
            continue

        author = str(r.get("Author", "")) if "Author" in rows.columns else ""
        language = str(r.get("Language", "")) if "Language" in rows.columns else ""
        threat_level = str(r.get("Threat_Level", "")) if "Threat_Level" in rows.columns else ""
        threat_conf = (
            float(r.get("Threat_Confidence"))
            if "Threat_Confidence" in rows.columns and pd.notna(r.get("Threat_Confidence"))
            else None
        )

        for ioc_type, values in iocs.items():
            for ioc_value in sorted(values):
                details.append(
                    {
                        "IOC": ioc_value,
                        "IOC_Type": ioc_type,
                        "Threat_Confidence": threat_conf,
                        "Threat_Level": threat_level,
                        "Author": author,
                        "Language": language,
                        "Row_Index": int(idx) if isinstance(idx, (int, float)) and not pd.isna(idx) else str(idx),
                        "Texts": text,
                    }
                )

    if not details:
        empty = pd.DataFrame()
        return empty, empty

    detail_df = pd.DataFrame(details)
    # Make the second table (detailed) more readable.
    preferred_order = [
        "IOC",
        "IOC_Type",
        "Threat_Confidence",
        "Threat_Level",
        "Author",
        "Language",
        "Row_Index",
        "Texts",
    ]
    detail_cols = [c for c in preferred_order if c in detail_df.columns] + [
        c for c in detail_df.columns if c not in preferred_order
    ]
    detail_df = detail_df[detail_cols]

    # First table: unique IOC summary with aggregated threat statistics.
    agg = (
        detail_df.groupby(["IOC", "IOC_Type"], dropna=False)
        .agg(
            Occurrences=("IOC", "size"),
            Avg_Threat_Confidence=("Threat_Confidence", "mean"),
            Max_Threat_Confidence=("Threat_Confidence", "max"),
        )
        .reset_index()
    )

    # Add max threat level (severity) across occurrences.
    order = {"None": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    level_map = detail_df[["IOC", "IOC_Type", "Threat_Level"]].copy()
    level_map["_lvl"] = level_map["Threat_Level"].astype(str).map(order).fillna(0).astype(int)
    max_level = (
        level_map.sort_values("_lvl", ascending=False)
        .drop_duplicates(subset=["IOC", "IOC_Type"], keep="first")
        .rename(columns={"Threat_Level": "Max_Threat_Level"})
        [["IOC", "IOC_Type", "Max_Threat_Level"]]
    )
    summary_df = agg.merge(max_level, on=["IOC", "IOC_Type"], how="left")

    # Formatting: keep as numeric but round for display.
    for c in ["Avg_Threat_Confidence", "Max_Threat_Confidence"]:
        if c in summary_df.columns:
            summary_df[c] = summary_df[c].round(4)

    summary_df = summary_df.sort_values(
        by=["Max_Threat_Confidence", "Occurrences"], ascending=[False, False]
    )

    return summary_df.reset_index(drop=True), detail_df.reset_index(drop=True)


def _plot_threat_distribution(df: pd.DataFrame) -> go.Figure:
    if "Threat_Level" not in df.columns:
        fig = go.Figure()
        fig.add_annotation(text="Missing column: Threat_Level", showarrow=False)
        fig.update_layout(height=360)
        return fig

    counts = (
        df["Threat_Level"].astype(str).value_counts(dropna=False).rename_axis("Threat_Level").reset_index(name="Count")
    )

    fig = px.bar(
        counts,
        x="Threat_Level",
        y="Count",
        color="Threat_Level",
        title="Threat Level Distribution",
        color_discrete_sequence=px.colors.qualitative.Plotly,
    )
    fig.update_layout(showlegend=False)
    fig.update_layout(height=360, margin=dict(l=10, r=10, t=50, b=10))
    return fig


def _plot_language_distribution(df: pd.DataFrame) -> go.Figure:
    if "Language" not in df.columns:
        fig = go.Figure()
        fig.add_annotation(text="Missing column: Language", showarrow=False)
        fig.update_layout(height=320)
        return fig

    counts = (
        df["Language"].astype(str).value_counts(dropna=False).rename_axis("Language").reset_index(name="Count")
    )
    counts = counts.sort_values("Count", ascending=False).head(15)
    fig = px.bar(
        counts,
        x="Count",
        y="Language",
        orientation="h",
        color="Language",
        title="Top Languages",
        color_discrete_sequence=px.colors.qualitative.Plotly,
    )
    fig.update_layout(showlegend=False)
    fig.update_layout(height=320, margin=dict(l=10, r=10, t=50, b=10))
    fig.update_yaxes(autorange="reversed")
    return fig


def _plot_confidence_histogram(df: pd.DataFrame) -> go.Figure:
    if "Threat_Confidence" not in df.columns:
        fig = go.Figure()
        fig.add_annotation(text="Missing column: Threat_Confidence", showarrow=False)
        fig.update_layout(height=320)
        return fig

    conf = pd.to_numeric(df["Threat_Confidence"], errors="coerce").dropna()
    if conf.empty:
        fig = go.Figure()
        fig.add_annotation(text="No numeric Threat_Confidence values", showarrow=False)
        fig.update_layout(height=320)
        return fig

    hist_df = pd.DataFrame({"Threat_Confidence": conf})
    fig = px.histogram(
        hist_df,
        x="Threat_Confidence",
        nbins=20,
        title="Threat Confidence Histogram",
        color_discrete_sequence=px.colors.qualitative.Plotly,
    )
    fig.update_traces(marker_line_width=0)
    fig.update_layout(height=320, margin=dict(l=10, r=10, t=50, b=10))
    return fig


def _top_authors_table(df: pd.DataFrame, *, top_n: int = 12) -> pd.DataFrame:
    if "Author" not in df.columns:
        return pd.DataFrame()

    rows = df.copy()
    if "Threat_Confidence" in rows.columns:
        rows["Threat_Confidence"] = pd.to_numeric(rows["Threat_Confidence"], errors="coerce")

    g = rows.groupby(rows["Author"].astype(str), dropna=False)
    out = pd.DataFrame(
        {
            "Author": g.size().index.astype(str),
            "Rows": g.size().values,
        }
    )
    if "Threat_Confidence" in rows.columns:
        out["Avg_Threat_Confidence"] = g["Threat_Confidence"].mean().values
        out["Max_Threat_Confidence"] = g["Threat_Confidence"].max().values
        out["Avg_Threat_Confidence"] = out["Avg_Threat_Confidence"].round(4)
        out["Max_Threat_Confidence"] = out["Max_Threat_Confidence"].round(4)

    out = out.sort_values(
        by=[c for c in ["Max_Threat_Confidence", "Rows"] if c in out.columns],
        ascending=[False, False][: len([c for c in ["Max_Threat_Confidence", "Rows"] if c in out.columns])],
    )
    return out.head(int(top_n)).reset_index(drop=True)


def _high_confidence_samples(df: pd.DataFrame, *, limit: int = 12) -> pd.DataFrame:
    if "Threat_Confidence" not in df.columns:
        return pd.DataFrame()

    rows = df.copy()
    rows["Threat_Confidence"] = pd.to_numeric(rows["Threat_Confidence"], errors="coerce")
    rows = rows.dropna(subset=["Threat_Confidence"])
    if rows.empty:
        return pd.DataFrame()

    cols = [c for c in ["Author", "Language", "Threat_Level", "Threat_Confidence", "Texts"] if c in rows.columns]
    rows = rows[cols].sort_values("Threat_Confidence", ascending=False).head(int(limit)).copy()

    if "Texts" in rows.columns:
        rows["Texts_Snippet"] = rows["Texts"].astype(str).str.replace(r"\s+", " ", regex=True).str.slice(0, 160)
        rows = rows.drop(columns=["Texts"])

    if "Threat_Confidence" in rows.columns:
        rows["Threat_Confidence"] = rows["Threat_Confidence"].round(4)

    return rows.reset_index(drop=True)


def _plot_relationship_network(
    df: pd.DataFrame,
    *,
    max_authors: int,
    min_edge_weight: int,
    label_top_n: int,
) -> Tuple[go.Figure, str]:
    g = build_relationship_graph(df, max_authors=max_authors)

    if g.number_of_nodes() == 0:
        fig = go.Figure()
        fig.add_annotation(text="Not enough columns to build graph", showarrow=False)
        fig.update_layout(height=650)
        return fig, "(no graph)"

    # Filter weak links to reduce visual noise.
    if min_edge_weight > 1:
        remove_edges = [(u, v) for u, v, d in g.edges(data=True) if d.get("weight", 1) < min_edge_weight]
        g.remove_edges_from(remove_edges)

    if g.number_of_nodes() == 0:
        fig = go.Figure()
        fig.add_annotation(text="Graph empty after filtering", showarrow=False)
        fig.update_layout(height=650)
        return fig, "(no graph)"

    centrality = nx.degree_centrality(g)
    degree = dict(g.degree())

    def kind_of(node: str) -> str:
        return str(g.nodes[node].get("kind", ""))

    kinds: dict[str, list[str]] = {"author": [], "lang": [], "threat": []}
    for n in g.nodes:
        k = kind_of(n)
        if k in kinds:
            kinds[k].append(n)

    # Seed positions in lanes (authors left, languages center, threats right),
    # then let the force layout refine a clean composition.
    pos_seed: dict[str, tuple[float, float]] = {}

    def seed_positions(nodes: list[str], x: float) -> None:
        if not nodes:
            return
        nodes_sorted = sorted(nodes, key=lambda n: centrality.get(n, 0.0), reverse=True)
        n_total = len(nodes_sorted)
        for i, node in enumerate(nodes_sorted):
            y = 0.0 if n_total == 1 else (i / (n_total - 1) - 0.5) * 2.0
            pos_seed[node] = (x, y)

    seed_positions(kinds["author"], -0.95)
    seed_positions(kinds["lang"], 0.0)
    seed_positions(kinds["threat"], 0.95)

    n_nodes = max(1, g.number_of_nodes())
    k = 0.65 / (n_nodes ** 0.5)
    pos = nx.spring_layout(g, pos=pos_seed, seed=42, k=k, iterations=140, weight="weight", scale=1.0)

    xs = [pos[n][0] for n in pos]
    ys = [pos[n][1] for n in pos]
    min_x, max_x = min(xs), max(xs)
    min_y, max_y = min(ys), max(ys)

    def norm(v: float, lo: float, hi: float) -> float:
        if hi - lo < 1e-9:
            return 0.0
        return (v - lo) / (hi - lo) * 2.0 - 1.0

    # Normalize and compress slightly so the graph stays centered and readable.
    pos = {n: (0.95 * norm(pos[n][0], min_x, max_x), 0.92 * norm(pos[n][1], min_y, max_y)) for n in pos}

    palette = px.colors.qualitative.Plotly

    def _hex_to_rgba(hex_color: str, alpha: float) -> str:
        c = (hex_color or "").strip().lstrip("#")
        if len(c) != 6:
            return f"rgba(120,120,120,{alpha})"
        r = int(c[0:2], 16)
        g2 = int(c[2:4], 16)
        b = int(c[4:6], 16)
        a = max(0.0, min(float(alpha), 1.0))
        return f"rgba({r},{g2},{b},{a})"

    kind_color = {"author": palette[0], "lang": palette[2], "threat": palette[1]}
    kind_symbol = {"author": "circle", "lang": "square", "threat": "diamond"}

    # Edges: bucket by weight to convey relationship strength.
    buckets = [
        ("Weak", 1, 1, 0.12, palette[5], 1),
        ("Medium", 2, 3, 0.18, palette[1], 2),
        ("Strong", 4, 10_000, 0.24, palette[2], 3),
    ]
    bucket_xy: dict[str, tuple[list[float], list[float]]] = {b[0]: ([], []) for b in buckets}

    def bucket_key(w: int) -> str:
        for name, lo, hi, *_ in buckets:
            if lo <= w <= hi:
                return name
        return "Weak"

    for u, v, d in g.edges(data=True):
        if u not in pos or v not in pos:
            continue
        w = int(d.get("weight", 1))
        key = bucket_key(w)
        xs_b, ys_b = bucket_xy[key]
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        xs_b.extend([x0, x1, None])
        ys_b.extend([y0, y1, None])

    edge_traces: list[go.Scatter] = []
    for name, _lo, _hi, alpha, color, width in buckets:
        xs_b, ys_b = bucket_xy[name]
        if not xs_b:
            continue
        edge_traces.append(
            go.Scatter(
                x=xs_b,
                y=ys_b,
                mode="lines",
                line=dict(width=width, color=_hex_to_rgba(color, alpha), shape="spline"),
                hoverinfo="none",
                showlegend=False,
            )
        )

    # Nodes: glow + solid, with symbols and legend.
    node_traces: list[go.Scatter] = []
    for kind in ["author", "lang", "threat"]:
        nodes = [n for n in kinds[kind] if n in pos]
        if not nodes:
            continue

        x = [pos[n][0] for n in nodes]
        y = [pos[n][1] for n in nodes]
        sizes = [12.0 + 50.0 * centrality.get(n, 0.0) for n in nodes]
        labels = [str(g.nodes[n].get("label", n)) for n in nodes]
        hover = [
            f"{labels[i]}<br>Type: {kind}<br>Degree: {degree.get(nodes[i], 0)}<br>Centrality: {centrality.get(nodes[i], 0.0):.3f}"
            for i in range(len(nodes))
        ]
        col = kind_color.get(kind, palette[4])
        sym = kind_symbol.get(kind, "circle")

        # Glow
        node_traces.append(
            go.Scatter(
                x=x,
                y=y,
                mode="markers",
                marker=dict(size=[s * 1.8 for s in sizes], color=col, opacity=0.14, symbol=sym, line=dict(width=0)),
                hoverinfo="none",
                showlegend=False,
            )
        )

        # Solid (legend)
        legend_name = "Authors" if kind == "author" else ("Languages" if kind == "lang" else "Threat Levels")
        node_traces.append(
            go.Scatter(
                x=x,
                y=y,
                mode="markers",
                name=legend_name,
                marker=dict(
                    size=sizes,
                    color=col,
                    opacity=0.92,
                    symbol=sym,
                    line=dict(width=1.2, color="rgba(255,255,255,0.35)"),
                ),
                text=hover,
                hoverinfo="text",
                showlegend=True,
            )
        )

    # Labels: show top N nodes by centrality for detail without clutter.
    labels_trace: Optional[go.Scatter] = None
    if int(label_top_n) > 0:
        sorted_nodes = sorted(pos.keys(), key=lambda n: centrality.get(n, 0.0), reverse=True)[: int(label_top_n)]
        labels_trace = go.Scatter(
            x=[pos[n][0] for n in sorted_nodes],
            y=[pos[n][1] for n in sorted_nodes],
            mode="text",
            text=[str(g.nodes[n].get("label", n)) for n in sorted_nodes],
            textposition="top center",
            textfont=dict(size=11),
            hoverinfo="none",
            showlegend=False,
        )

    fig = go.Figure(data=[*edge_traces, *node_traces] + ([labels_trace] if labels_trace else []))
    fig.update_layout(
        height=650,
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0.0),
        hovermode="closest",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )

    top_node = max(centrality, key=centrality.get)
    top_label = str(g.nodes[top_node].get("label", top_node))
    return fig, top_label


def generate_summary_report(df: pd.DataFrame, *, top_graph_node: str) -> str:
    lines = []
    lines.append("DarkWeb CTI - Summary Report")
    lines.append("=")
    lines.append(f"Total rows: {len(df)}")

    if "Author" in df.columns:
        lines.append(f"Unique authors: {df['Author'].nunique(dropna=True)}")

    if "Language" in df.columns:
        top_lang = df["Language"].value_counts(dropna=False).head(1)
        if len(top_lang) == 1:
            lines.append(f"Top language: {top_lang.index[0]} ({int(top_lang.iloc[0])})")

    if "Threat_Level" in df.columns:
        top_threat = df["Threat_Level"].value_counts(dropna=False).head(1)
        if len(top_threat) == 1:
            lines.append(f"Top threat level: {top_threat.index[0]} ({int(top_threat.iloc[0])})")

    if "Threat_Confidence" in df.columns:
        mean_conf = pd.to_numeric(df["Threat_Confidence"], errors="coerce").mean()
        if pd.notna(mean_conf):
            lines.append(f"Avg threat confidence: {mean_conf:.3f}")

    lines.append(f"Top graph node (by degree centrality): {top_graph_node}")

    return "\n".join(lines) + "\n"


def main() -> None:
    st.set_page_config(
        page_title="DarkWeb CTI Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    _inject_cyber_ui()

    st.markdown(
        """
        <div class="dwcti-hero">
            <div class="dwcti-hero-row">
                <div>
                    <div class="dwcti-title-wrap">
                        <span class="dwcti-mark" title="CTI">
                            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                <path d="M12 2.2 19.2 5.4v6.6c0 5.3-3.4 9.2-7.2 10.8C8.2 21.2 4.8 17.3 4.8 12V5.4L12 2.2Zm0 2.1-5.2 2.3v5.4c0 4.2 2.6 7.4 5.2 8.6 2.6-1.2 5.2-4.4 5.2-8.6V6.6L12 4.3Z"/>
                            </svg>
                        </span>
                        <div class="dwcti-title">DarkWeb CTI Dashboard</div>
                    </div>
                    <div class="dwcti-subtitle">Multilingual threat labeling and IOC extraction from dark web CTI data (Supabase Postgres)</div>
                </div>
                <div class="dwcti-badges">
                    <div class="dwcti-badge dwcti-badge--accent">
                        <svg class="dwcti-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                            <path d="M12 3c4.2 0 7.5 1.3 7.5 3v12c0 1.7-3.3 3-7.5 3S4.5 19.7 4.5 18V6c0-1.7 3.3-3 7.5-3Zm0 2C8.1 5 6.5 5.9 6.5 6s1.6 1 5.5 1 5.5-.9 5.5-1-1.6-1-5.5-1Zm0 4c-2.5 0-4.6-.4-5.5-1v2c0 .6 2.1 1 5.5 1s5.5-.4 5.5-1V8c-.9.6-3 1-5.5 1Zm0 4c-2.5 0-4.6-.4-5.5-1v2c0 .6 2.1 1 5.5 1s5.5-.4 5.5-1v-2c-.9.6-3 1-5.5 1Zm0 4c-2.5 0-4.6-.4-5.5-1v2c0 .6 2.1 1 5.5 1s5.5-.4 5.5-1v-2c-.9.6-3 1-5.5 1Z"/>
                        </svg>
                        Data: Postgres
                    </div>
                    <div class="dwcti-badge">
                        <svg class="dwcti-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                            <path d="M12 2.5a9.5 9.5 0 1 0 9.5 9.5A9.5 9.5 0 0 0 12 2.5Zm0 2a7.5 7.5 0 0 1 7.5 7.5H17.8a5.8 5.8 0 0 0-5.8-5.8V4.5Zm0 4a3.5 3.5 0 0 1 3.5 3.5H13.8A1.8 1.8 0 0 0 12 10.2V8.5ZM12 14.2a2.2 2.2 0 1 1 0-4.4 2.2 2.2 0 0 1 0 4.4Z"/>
                        </svg>
                        Mode: Interactive
                    </div>
                    <div class="dwcti-badge">
                        <svg class="dwcti-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                            <path d="M12 4c4.4 0 8 3.1 9.6 7.4.1.4.1.8 0 1.2C20 16.9 16.4 20 12 20S4 16.9 2.4 12.6a1.7 1.7 0 0 1 0-1.2C4 7.1 7.6 4 12 4Zm0 3.2A4.8 4.8 0 1 0 16.8 12 4.8 4.8 0 0 0 12 7.2Zm0 2a2.8 2.8 0 1 1 0 5.6 2.8 2.8 0 0 1 0-5.6Z"/>
                        </svg>
                        Scope: Dark Web CTI
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.divider()

    with st.sidebar:
        st.markdown("### 🗄️ Data")
        with st.container(border=True):
            table = st.text_input("Table", value=DEFAULT_TABLE)
            st.caption(
                "Set `DATABASE_URL` or `PGHOST`/`PGPORT`/`PGDATABASE`/`PGUSER`/`PGPASSWORD` (and `PGSSLMODE=require`)."
            )

    # Load data
    df: pd.DataFrame
    source: DataSource

    db_id = _safe_db_id()
    try:
        df = _load_df_cached(db_id, table)
        source = DataSource("postgres", table)
    except Exception as e:
        with st.container(border=True):
            st.error(f"Postgres load failed: {type(e).__name__}: {e}")
            st.info(
                "Check that your Session Pooler env vars are set (PGHOST/PGPORT/PGDATABASE/PGUSER/PGPASSWORD, PGSSLMODE=require)."
            )
        st.stop()

    db_columns = list(df.columns)
    insert_colmap = _resolve_insert_columns(db_columns)

    df = coerce_columns(df)

    meta_left, meta_right = st.columns([3, 2])
    with meta_left:
        st.caption(f"Source: {source.kind} — {source.details}")
    with meta_right:
        refreshed = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        st.caption(f"Last loaded: {refreshed}")

    # Filters (after data load)
    with st.sidebar:
        st.markdown("### 🎛️ Controls")

        with st.expander("Filters", expanded=True):
            all_langs = (
                sorted(df["Language"].dropna().unique().astype(str).tolist())
                if "Language" in df.columns
                else []
            )
            all_threats = (
                sorted(df["Threat_Level"].dropna().unique().astype(str).tolist())
                if "Threat_Level" in df.columns
                else []
            )

            lang_filter = st.multiselect("Language", all_langs, default=all_langs)
            threat_filter = st.multiselect("Threat_Level", all_threats, default=all_threats)

        with st.expander("Network", expanded=True):
            max_authors = st.slider(
                "Max authors (graph)",
                min_value=5,
                max_value=60,
                value=20,
                step=1,
            )
            min_edge_weight = st.slider("Min link weight", min_value=1, max_value=10, value=1, step=1)
            label_top_n = st.slider("Label top nodes", min_value=0, max_value=25, value=8, step=1)

    filtered = df
    if "Language" in filtered.columns and lang_filter:
        filtered = filtered[filtered["Language"].astype(str).isin(lang_filter)]
    if "Threat_Level" in filtered.columns and threat_filter:
        filtered = filtered[filtered["Threat_Level"].astype(str).isin(threat_filter)]

    tab_overview, tab_ioc, tab_network, tab_data, tab_user = st.tabs(
        ["Overview", "IOC Extractor", "Network", "Data Preview", "User Input"]
    )

    with tab_overview:
        st.subheader("At a glance")
        with st.container(border=True):
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Rows", f"{len(filtered):,}")
            m2.metric(
                "Unique Authors",
                f"{filtered['Author'].nunique() if 'Author' in filtered.columns else '—'}",
            )
            m3.metric(
                "Languages",
                f"{filtered['Language'].nunique() if 'Language' in filtered.columns else '—'}",
            )
            m4.metric(
                "Avg Confidence",
                f"{filtered['Threat_Confidence'].mean():.3f}" if "Threat_Confidence" in filtered.columns else "—",
            )

        main_left, main_right = st.columns([2, 1])
        with main_left:
            with st.container(border=True):
                st.markdown("**Threat distribution**")
                bar_fig = _plot_threat_distribution(filtered)
                st.plotly_chart(bar_fig, use_container_width=True)

        with main_right:
            with st.container(border=True):
                st.markdown("**Dataset summary**")
                net_fig, top_label = _plot_relationship_network(
                    filtered,
                    max_authors=max_authors,
                    min_edge_weight=min_edge_weight,
                    label_top_n=label_top_n,
                )
                report = generate_summary_report(filtered, top_graph_node=top_label)
                st.code(report, language="text")

        st.subheader("Signals")
        s1, s2, s3 = st.columns(3)
        with s1:
            with st.container(border=True):
                st.markdown("**Languages**")
                st.plotly_chart(_plot_language_distribution(filtered), use_container_width=True)

        with s2:
            with st.container(border=True):
                st.markdown("**Confidence**")
                st.plotly_chart(_plot_confidence_histogram(filtered), use_container_width=True)

        with s3:
            with st.container(border=True):
                st.markdown("**Top authors (by max confidence)**")
                top_auth = _top_authors_table(filtered, top_n=12)
                if top_auth.empty:
                    st.info("No author information available in the current filter.")
                else:
                    st.dataframe(top_auth, use_container_width=True, height=320)

        with st.container(border=True):
            st.markdown("**High-confidence samples**")
            samples = _high_confidence_samples(filtered, limit=12)
            if samples.empty:
                st.info("No numeric confidence values to sample.")
            else:
                st.dataframe(samples, use_container_width=True, height=360)

    with tab_network:
        st.subheader("Relationship network")
        st.caption(
            "Visualizes author-to-author relationships inferred from co-occurrence patterns in the dataset. "
            "Use the sidebar controls to adjust graph size and labeling."
        )
        with st.container(border=True):
            net_fig, _ = _plot_relationship_network(
                filtered,
                max_authors=max_authors,
                min_edge_weight=min_edge_weight,
                label_top_n=label_top_n,
            )
            st.plotly_chart(net_fig, use_container_width=True)

    with tab_ioc:
        st.subheader("IOC Extractor")
        st.caption(
            "Lists Indicators of Compromise (IOCs) found in all DB-loaded texts using the same regex IOC extractor as the threat labeler."
        )

        summary_df, detail_df = build_ioc_tables(df)
        ioc_left, ioc_right = st.columns([1, 2])

        with ioc_left:
            with st.container(border=True):
                st.markdown("**IOC Summary**")
                if summary_df.empty:
                    st.info("No IOCs were detected in the current dataset.")
                else:
                    st.dataframe(summary_df, use_container_width=True, height=520)

        with ioc_right:
            with st.container(border=True):
                st.markdown("**IOC Details (per occurrence)**")
                if detail_df.empty:
                    st.info("No IOC occurrences to display.")
                else:
                    st.dataframe(detail_df, use_container_width=True, height=520)

    with tab_data:
        with st.container(border=True):
            st.subheader("Data preview")
            st.caption("Shows the currently filtered rows.")
            st.dataframe(filtered, use_container_width=True, height=650)

    with tab_user:
        st.subheader("Label a new post")
        st.caption(
            "Enter an Author and Texts. The dashboard will detect Language first, then compute Threat_Confidence/Threat_Level, "
            "apply author-correlation weightage using existing DB history, save the labeled row into Postgres, and refresh the dashboard."
        )

        # Show the last run result after refresh.
        last = st.session_state.get("last_user_label")
        inserted = st.session_state.pop("last_user_inserted", None)
        if inserted and last:
            st.success("Saved to database and refreshed dashboard.")

        with st.container(border=True):
            st.markdown("**New input**")
            with st.form("user_input_form", clear_on_submit=False):
                author_in = st.text_input("Author", value="")
                text_in = st.text_area("Texts", value="", height=180)
                submitted = st.form_submit_button("Check, label, and save")

        last_details = st.session_state.get("last_user_label_details")
        if last and last_details:
            with st.container(border=True):
                st.markdown("**Labeling result**")
                r1, r2, r3, r4 = st.columns(4)
                r1.metric("Detected language", last.get("Language", "—"))
                r2.metric("Threat level", last.get("Threat_Level", "—"))
                r3.metric("Threat confidence", f"{float(last.get('Threat_Confidence', 0.0)):.4f}")
                r4.metric("Author Weight (alpha)", f"{float(last.get('Author_Alpha', 0.0)):.2f}")
                st.caption(
                    f"Base confidence: {float(last.get('Base_Confidence', 0.0)):.4f}. "
                    f"Author prior: {float(last.get('Author_Prior', 0.0)):.4f}."
                )

                st.markdown("**Threat evidence**")
                st.write(
                    {
                        "ioc_hit_count": int(last_details.get("ioc_count", 0)),
                        "keyword_hit_count": int(last_details.get("kw_count", 0)),
                        "ioc_raw_score": f"{float(last_details.get('ioc_raw', 0.0)):.4f}",
                        "keyword_raw_score": f"{float(last_details.get('kw_raw', 0.0)):.4f}",
                        "combined_raw_score": f"{float(last_details.get('combined_raw', 0.0)):.4f}",
                        "keyword_hits": last_details.get("kw_hits", {}),
                        "cap_reason": last_details.get("cap_reason", ""),
                    }
                )

                with st.expander("Show calculation details", expanded=True):
                    st.dataframe(pd.DataFrame(last_details.get("calc_summary", [])), use_container_width=True, hide_index=True)

                    st.markdown("**Author correlation details**")
                    st.write(
                        {
                            "same_author_rows": int(last_details.get("author_rows", 0)),
                            "author_history_avg_confidence": round(float(last_details.get("author_avg", 0.0)), 4),
                            "author_history_max_confidence": round(float(last_details.get("author_max", 0.0)), 4),
                            "author_prior_confidence": round(float(last_details.get("author_prior", 0.0)), 4),
                            "alpha_value": round(float(last_details.get("alpha", 0.0)), 4),
                        }
                    )
                    if last_details.get("author_preview"):
                        st.markdown("**Past author data used for this decision**")
                        st.dataframe(pd.DataFrame(last_details.get("author_preview")), use_container_width=True, hide_index=True)

                with st.expander("Threat Explanations", expanded=False):
                    st.markdown("**Plain-language explanation of why this post was labeled that way**")
                    explanation_text = last_details.get("threat_explanation", "")
                    st.write(explanation_text)

                    st.markdown("**What the system looked at**")
                    st.write(
                        [
                            "The words and phrases in your input text.",
                            "Any IOCs, such as IP addresses, URLs, domains, hashes, or email addresses.",
                            "Threat-related keywords that match the language used in the text.",
                            "The author's previous posts in the database, if the same author was found before.",
                        ]
                    )

                    st.markdown("**Why the result can become Critical, High, Low, or None**")
                    st.write(
                        [
                            "Critical means the input strongly matched high-severity threat terms, or the score became high enough after all evidence was combined.",
                            "High means the input showed clear threat signs, but not as many or not as severe as Critical.",
                            "Low means there were some warning signs, but the evidence was weaker or more limited.",
                            "None means the input had little to no strong threat evidence.",
                        ]
                    )

                    st.markdown("**How the score was formed in simple terms**")
                    st.write(
                        [
                            f"IOCs were counted first. These are technical signs like IPs, links, hashes, or email addresses. In this case, the text had {int(last_details.get('ioc_count', 0))} IOC hit(s).",
                            f"Threat keywords were then counted. The text had {int(last_details.get('kw_count', 0))} keyword hit(s), and the matched keywords were: {', '.join(sorted(last_details.get('kw_hits', {}).keys())) or 'none' }.",
                            f"The system gave more weight to stronger evidence, so the raw score became {float(last_details.get('combined_raw', 0.0)):.4f} before it was turned into confidence.",
                            f"After that, the score was blended with the author's previous posts. If this author had similar past posts, the final score could rise a little more.",
                        ]
                    )

                    st.markdown("**What the author history means**")
                    st.write(
                        [
                            f"The system found {int(last_details.get('author_rows', 0))} previous row(s) from the same author.",
                            f"Their past average confidence was {float(last_details.get('author_avg', 0.0)):.4f}, and the strongest past post reached {float(last_details.get('author_max', 0.0)):.4f}.",
                            f"The author prior used in the final decision was {float(last_details.get('author_prior', 0.0)):.4f}.",
                            f"The author influence value (alpha) was {float(last_details.get('alpha', 0.0)):.2f}, which means the old data had a {float(last_details.get('alpha', 0.0)):.0%} influence on the final score.",
                        ]
                    )

                    st.markdown("**Why the level was capped or limited**")
                    st.write(
                        [
                            f"The strongest matched keyword had a danger weight of {float(last_details.get('max_keyword_weight', 0.0)):.2f}.",
                            f"Because of that, the result was limited using this rule: {last_details.get('cap_reason', 'No cap rule found')}.",
                            "This prevents a post from being marked too severe just because it contains many small signals that are not highly dangerous.",
                        ]
                    )

                    st.markdown("**Helpful way to read the output**")
                    st.write(
                        [
                            "If the score is high, it does not always mean the post is definitely dangerous; it means the text matched several strong warning signs.",
                            "If the author has a risky posting history, the system may slightly raise the final result because past behavior is also a clue.",
                            "If there are no strong threat words or IOCs, the system stays near None or Low.",
                            "Think of the result as a short summary of what the text looks like, not as a final human judgment.",
                        ]
                    )

        if submitted:
            author_clean = (author_in or "").strip()
            text_clean = (text_in or "").strip()
            if not author_clean or not text_clean:
                st.error("Both Author and Texts are required.")
            else:
                # 1) Language labeling (same keyword-based method, applied to the user input)
                lang_dbg = label_language_with_debug(text_clean, mode="scored")
                language = lang_dbg.label

                # 2) Threat labeling (same standalone formulas)
                params = ScoringParams()
                base = label_single_text(author=author_clean, text=text_clean, language=language, params=params)

                # 3) Author correlation weightage using DB history
                final_conf, alpha, author_prior, author_rows = author_correlation_adjustment(
                    df,
                    author=author_clean,
                    base_confidence=base.base_confidence,
                )

                # If there is no lexical/IOC evidence, allow author-correlation to influence level directly.
                if base.ioc_hit_count or base.keyword_hit_count:
                    final_level = confidence_to_level_capped(final_conf, base.max_keyword_weight)
                else:
                    final_level = confidence_to_level(final_conf)

                tokens = tokenize(text_clean)
                iocs = extract_iocs(text_clean)
                ioc_raw, ioc_count = ioc_score(iocs)
                kw_raw, kw_count, kw_hits = keyword_score(text_clean, language, tokens)
                combined_raw = (2.0 * ioc_raw) + kw_raw
                base_conf_from_formula = raw_to_confidence(combined_raw, params.raw_scale)
                ioc_multiplier = 1.0 + (params.ioc_multiplier_per_hit * ioc_count)
                keyword_multiplier = 1.0 + (params.keyword_multiplier_per_hit * kw_count)
                capped_level = confidence_to_level_capped(base.base_confidence, base.max_keyword_weight)
                if base.max_keyword_weight >= 4.0:
                    cap_reason = "Critical cap from weapons/explosives keywords"
                elif base.max_keyword_weight >= 3.4:
                    cap_reason = "High cap from hard-drug or high-severity keywords"
                elif base.max_keyword_weight >= 3.0:
                    cap_reason = "Medium cap from controlled-substance keywords"
                elif base.max_keyword_weight >= 2.4:
                    cap_reason = "Low cap from cannabis-family keywords"
                else:
                    cap_reason = "None cap because no high-severity keyword matched"

                author_history = pd.DataFrame()
                author_avg = 0.0
                author_max = 0.0
                author_snippet_cols = [
                    c
                    for c in ["Threat_Confidence", "Threat_Level", "Language", "Texts"]
                    if c in df.columns
                ]
                if "Author" in df.columns and "Threat_Confidence" in df.columns:
                    author_mask = df["Author"].astype(str).str.strip().str.lower() == author_clean.lower()
                    author_history = df.loc[author_mask, author_snippet_cols].copy()
                    if not author_history.empty:
                        author_history["Threat_Confidence"] = pd.to_numeric(
                            author_history["Threat_Confidence"], errors="coerce"
                        )
                        author_history = author_history.dropna(subset=["Threat_Confidence"])
                        if not author_history.empty:
                            author_avg = float(author_history["Threat_Confidence"].mean())
                            author_max = float(author_history["Threat_Confidence"].max())

                calc_summary = pd.DataFrame(
                    [
                        {"Stage": "Language detection", "Value": language, "Notes": "Detected from language keywords"},
                        {"Stage": "IOC count", "Value": int(base.ioc_hit_count), "Notes": f"Raw IOC types: {', '.join(sorted((base.iocs or {}).keys())) or 'none'}"},
                        {"Stage": "Keyword count", "Value": int(base.keyword_hit_count), "Notes": "Threat keyword matches in the text"},
                        {"Stage": "IOC raw score", "Value": f"{ioc_raw:.4f}", "Notes": f"Weighted by IOC type: {', '.join(sorted((base.iocs or {}).keys())) or 'none'}"},
                        {"Stage": "Keyword raw score", "Value": f"{kw_raw:.4f}", "Notes": "Sum of universal + language-specific keyword weights"},
                        {"Stage": "Combined raw score", "Value": f"{combined_raw:.4f}", "Notes": "(2.0 x IOC raw) + keyword raw"},
                        {"Stage": "Raw-to-confidence map", "Value": f"{base_conf_from_formula:.4f}", "Notes": f"1 - exp(-raw / {params.raw_scale:.1f})"},
                        {"Stage": "IOC multiplier", "Value": f"x{ioc_multiplier:.4f}", "Notes": f"+{params.ioc_multiplier_per_hit:.0%} per IOC hit"},
                        {"Stage": "Keyword multiplier", "Value": f"x{keyword_multiplier:.4f}", "Notes": f"+{params.keyword_multiplier_per_hit:.0%} per keyword hit"},
                        {"Stage": "Base confidence", "Value": f"{base.base_confidence:.4f}", "Notes": f"Same as the standalone labeler output ({base.base_level})"},
                        {"Stage": "Level cap", "Value": capped_level, "Notes": cap_reason},
                        {"Stage": "Final confidence", "Value": f"{final_conf:.4f}", "Notes": "Base confidence blended with author history"},
                        {"Stage": "Final level", "Value": final_level, "Notes": "Final threat label shown to the user"},
                    ]
                )

                preview = pd.DataFrame()
                if not author_history.empty:
                    preview = author_history.copy()
                    preview["Texts"] = preview["Texts"].astype(str).str.replace(r"\s+", " ", regex=True).str.slice(0, 220)
                    preview = preview.sort_values("Threat_Confidence", ascending=False).head(10)

                explanation_lines = []
                explanation_lines.append(f"Threat level = {final_level} because the final confidence score is {final_conf:.4f}.")
                explanation_lines.append("Thresholds: Critical >=0.85, High >=0.70, Medium >=0.50, Low >=0.25, None <0.25.")
                if base.ioc_hit_count:
                    explanation_lines.append(f"Detected {int(base.ioc_hit_count)} IOC(s) (e.g., IPs, URLs, hashes); these increase confidence.")
                if base.keyword_hit_count:
                    explanation_lines.append(f"Found {int(base.keyword_hit_count)} threat keyword hits; some keywords carry higher severity and can cap the level.")
                explanation_lines.append(f"Highest keyword severity matched: {base.max_keyword_weight:.2f} (used to cap severity: {cap_reason}).")
                explanation_lines.append(f"Author history contributed with prior average {author_prior:.4f} and alpha={alpha:.2f} to blend the final score.")
                explanation_text = "\n\n".join(explanation_lines)

                # 4) Save into Postgres, then refresh cached data.
                try:
                    missing_cols = [
                        c
                        for c in ["Author", "Texts", "Language", "Threat_Confidence", "Threat_Level"]
                        if c not in insert_colmap
                    ]
                    if missing_cols:
                        raise RuntimeError(
                            "Table is missing required columns for insertion: "
                            f"{missing_cols}. Found columns: {db_columns}"
                        )

                    row_db = {
                        insert_colmap["Author"]: author_clean,
                        insert_colmap["Texts"]: text_clean,
                        insert_colmap["Language"]: language,
                        insert_colmap["Threat_Confidence"]: f"{final_conf:.4f}",
                        insert_colmap["Threat_Level"]: final_level,
                    }
                    insert_into_postgres(table, row_db)

                    row = {
                        "Author": author_clean,
                        "Texts": text_clean,
                        "Language": language,
                        "Threat_Confidence": f"{final_conf:.4f}",
                        "Threat_Level": final_level,
                    }

                    # persist full user-visible row plus calculation details so the UI can show them
                    st.session_state["last_user_label"] = {
                        **row,
                        "Author_Alpha": float(alpha),
                        "Author_Prior": float(author_prior),
                        "Base_Confidence": float(base.base_confidence),
                    }

                    # Prepare a lightweight, serializable calculation summary and author preview
                    calc_summary_records = [
                        {"Stage": rec.get("Stage"), "Value": rec.get("Value"), "Notes": rec.get("Notes")} for rec in (
                            calc_summary.to_dict(orient="records") if isinstance(calc_summary, pd.DataFrame) else []
                        )
                    ]

                    author_preview_records = []
                    if not preview.empty:
                        author_preview_records = preview.to_dict(orient="records")

                    st.session_state["last_user_label_details"] = {
                        "calc_summary": calc_summary_records,
                        "ioc_raw": float(ioc_raw),
                        "ioc_count": int(ioc_count),
                        "kw_raw": float(kw_raw),
                        "kw_count": int(kw_count),
                        "kw_hits": dict(kw_hits),
                        "combined_raw": float(combined_raw),
                        "base_conf_from_formula": float(base_conf_from_formula),
                        "ioc_multiplier": float(ioc_multiplier),
                        "keyword_multiplier": float(keyword_multiplier),
                        "cap_reason": cap_reason,
                        "capped_level": capped_level,
                        "author_rows": int(author_rows),
                        "author_avg": float(author_avg),
                        "author_max": float(author_max),
                        "author_prior": float(author_prior),
                        "alpha": float(alpha),
                        "author_preview": author_preview_records,
                        "threat_explanation": explanation_text,
                    }
                    st.session_state["last_user_inserted"] = True

                    st.cache_data.clear()
                    st.rerun()
                except Exception as e:
                    st.error(f"Insert failed: {type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
