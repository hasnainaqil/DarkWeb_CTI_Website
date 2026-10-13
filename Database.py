from __future__ import annotations

import argparse
import csv
import getpass
import os
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

import psycopg2


def _quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _parse_schema_table(value: str) -> Tuple[str, str]:
    if "." in value:
        schema, table = value.split(".", 1)
        return schema, table
    return "public", value


def _get_password(explicit: Optional[str]) -> str:
    if explicit:
        return explicit
    env = os.getenv("PGPASSWORD")
    if env:
        return env
    return getpass.getpass("Supabase Postgres password (PGPASSWORD): ")


def _read_csv_header(csv_path: Path) -> List[str]:
    with csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
    cols = [c.strip() for c in header]
    if not cols or any(c == "" for c in cols):
        raise ValueError("CSV header row is empty or contains empty column names")
    return cols


def _column_type(col_name: str) -> str:
    # Keep schema simple and compatible; only Threat_Confidence is stored as numeric.
    if col_name.strip().lower() == "threat_confidence":
        return "DOUBLE PRECISION"
    return "TEXT"


def setup_and_upload(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Upload CSV to Supabase Postgres (COPY)")
    p.add_argument(
        "--csv",
        default=str(Path(__file__).with_name("language_dataset_threat_labeled.csv")),
        help="CSV file path (default: language_dataset_threat_labeled.csv next to this script)",
    )
    p.add_argument(
        "--table",
        default="threat_intelligence_data",
        help="Target table name (optionally schema.table). Default: threat_intelligence_data",
    )
    p.add_argument("--create-table", action="store_true", help="Create table if it doesn't exist")
    p.add_argument("--truncate", action="store_true", help="Truncate the table before import")

    # Connection defaults for Supabase (override via env vars or flags)
    p.add_argument("--host", default=os.getenv("PGHOST", "db.ypefuoljwvczzmivbgmb.supabase.co"), help="DB host")
    p.add_argument("--port", type=int, default=int(os.getenv("PGPORT", "5432")), help="DB port")
    p.add_argument("--database", default=os.getenv("PGDATABASE", "postgres"), help="DB name")
    p.add_argument("--user", default=os.getenv("PGUSER", "postgres"), help="DB user")
    p.add_argument("--password", default=None, help="DB password (avoid; prefer PGPASSWORD env var)")
    p.add_argument("--sslmode", default=os.getenv("PGSSLMODE", "require"), help="SSL mode (Supabase: require)")

    args = p.parse_args(argv)

    csv_path = Path(args.csv)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    # Use the CSV header as the source of truth for column names and order.
    columns = _read_csv_header(csv_path)

    schema, table = _parse_schema_table(args.table)
    password = _get_password(args.password)

    conn = psycopg2.connect(
        host=args.host,
        port=args.port,
        dbname=args.database,
        user=args.user,
        password=password,
        sslmode=args.sslmode,
    )

    full_name = f"{_quote_ident(schema)}.{_quote_ident(table)}"
    cols_sql = ", ".join(_quote_ident(c) for c in columns)

    create_cols_sql = ", ".join(f"{_quote_ident(c)} {_column_type(c)}" for c in columns)
    create_sql = f"CREATE TABLE IF NOT EXISTS {full_name} ({create_cols_sql});"

    copy_sql = (
        f"COPY {full_name} ({cols_sql}) "
        "FROM STDIN WITH (FORMAT csv, HEADER true, DELIMITER ',', QUOTE '\"', ESCAPE '\"');"
    )

    try:
        with conn:
            with conn.cursor() as cur:
                if args.create_table:
                    cur.execute(create_sql)
                if args.truncate:
                    cur.execute(f"TRUNCATE TABLE {full_name};")

                print(f"--- Uploading CSV via COPY ---")
                print(f"CSV: {csv_path}")
                print(f"Table: {schema}.{table}")

                with csv_path.open("r", encoding="utf-8", newline="") as f:
                    cur.copy_expert(copy_sql, f)

                cur.execute(f"SELECT COUNT(*) FROM {full_name};")
                row_count = cur.fetchone()[0]

        print("Upload Successful! Your data is now in the database.")
        print(f"Row count in {schema}.{table}: {row_count}")
        return 0
    finally:
        conn.close()

if __name__ == "__main__":
    raise SystemExit(setup_and_upload())