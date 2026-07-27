from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Iterator
from urllib import parse


def normalise_url(raw: str) -> str | None:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if raw.startswith("{"):
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(item, dict):
            return None
        found = False
        for key in ("url", "final_url", "input", "target"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                raw = value.strip()
                found = True
                break
        if not found:
            return None
    else:
        raw = raw.split()[0]

    if raw.startswith("//"):
        raw = "https:" + raw
    if "://" not in raw:
        raw = "https://" + raw

    parsed = parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def url_fingerprint(url: str) -> int:
    return int.from_bytes(hashlib.blake2b(url.encode("utf-8"), digest_size=8).digest(), "big")


def iter_urls(
    path: Path,
    max_urls: int | None = None,
    dedup_db: Path | None = None,
) -> Iterator[str]:
    seen: set[int] | None = set() if dedup_db is None else None
    connection: sqlite3.Connection | None = None
    if dedup_db is not None:
        dedup_db.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(dedup_db)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        connection.execute("CREATE TABLE IF NOT EXISTS seen_urls (url TEXT PRIMARY KEY)")

    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                url = normalise_url(line)
                if not url:
                    continue
                if connection is not None:
                    cursor = connection.execute("INSERT OR IGNORE INTO seen_urls(url) VALUES (?)", (url,))
                    if cursor.rowcount == 0:
                        continue
                    if count % 1000 == 0:
                        connection.commit()
                else:
                    assert seen is not None
                    fingerprint = url_fingerprint(url)
                    if fingerprint in seen:
                        continue
                    seen.add(fingerprint)
                yield url
                count += 1
                if max_urls and count >= max_urls:
                    break
    finally:
        if connection is not None:
            connection.commit()
            connection.close()


def load_urls(path: Path, max_urls: int | None = None) -> list[str]:
    urls: list[str] = []
    for url in iter_urls(path, max_urls=max_urls):
        urls.append(url)
    return urls


def add_query(url: str, params: dict[str, str]) -> str:
    parts = parse.urlsplit(url)
    query = parse.parse_qsl(parts.query, keep_blank_values=True)
    query.extend(params.items())
    return parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path or "/", parse.urlencode(query), parts.fragment)
    )


def add_raw_query(url: str, key: str, raw_value: str) -> str:
    parts = parse.urlsplit(url)
    sep = "&" if parts.query else ""
    query = f"{parts.query}{sep}{parse.quote(key)}={raw_value}"
    return parse.urlunsplit((parts.scheme, parts.netloc, parts.path or "/", query, parts.fragment))
