"""Dialect-aware SQL tokenizer, statement splitter, and intent classifier."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .models import ParsedStatement, StatementKind


@dataclass
class Token:
    kind: str  # "WORD", "STRING", "IDENT", "SYMBOL", "OP", "NUMBER"
    text: str
    start: int
    end: int

    @property
    def upper(self) -> str:
        if self.kind == "WORD":
            return self.text.upper()
        return self.text


def unquote_ident(text: str) -> str:
    if len(text) >= 2:
        if text[0] == '"' and text[-1] == '"':
            return text[1:-1].replace('""', '"')
        if text[0] == "`" and text[-1] == "`":
            return text[1:-1].replace("``", "`")
        if text[0] == "[" and text[-1] == "]":
            return text[1:-1]
    return text


def tokenize(sql: str) -> list[Token]:
    """Tokenize SQL ignoring whitespace and comments while preserving byte offsets."""
    tokens: list[Token] = []
    n = len(sql)
    i = 0

    while i < n:
        ch = sql[i]

        # Whitespace
        if ch.isspace():
            i += 1
            continue

        # Line comment --
        if ch == "-" and i + 1 < n and sql[i + 1] == "-":
            j = sql.find("\n", i + 2)
            i = n if j == -1 else j + 1
            continue

        # Block comment /* ... */
        if ch == "/" and i + 1 < n and sql[i + 1] == "*":
            j = sql.find("*/", i + 2)
            i = n if j == -1 else j + 2
            continue

        # Single-quoted string literal
        if ch == "'":
            start = i
            i += 1
            while i < n:
                if sql[i] == "\\":
                    i += 2
                    continue
                if sql[i] == "'":
                    if i + 1 < n and sql[i + 1] == "'":
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            tokens.append(Token("STRING", sql[start:i], start, i))
            continue

        # PostgreSQL dollar-quoted strings ($$...$$ or $tag$...$tag$)
        if ch == "$":
            j = i + 1
            while j < n and (sql[j].isalnum() or sql[j] == "_"):
                j += 1
            if j < n and sql[j] == "$":
                tag = sql[i : j + 1]
                close_pos = sql.find(tag, j + 1)
                end_pos = n if close_pos == -1 else close_pos + len(tag)
                tokens.append(Token("STRING", sql[i:end_pos], i, end_pos))
                i = end_pos
                continue

        # Double-quoted or backtick identifier
        if ch in ('"', "`"):
            quote = ch
            start = i
            i += 1
            while i < n:
                if sql[i] == quote:
                    if i + 1 < n and sql[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            tokens.append(Token("IDENT", sql[start:i], start, i))
            continue

        # Bracket identifier [...]
        if ch == "[":
            start = i
            j = sql.find("]", i + 1)
            i = n if j == -1 else j + 1
            tokens.append(Token("IDENT", sql[start:i], start, i))
            continue

        # Symbols
        if ch in ("(", ")", ",", ";", "."):
            tokens.append(Token("SYMBOL", ch, i, i + 1))
            i += 1
            continue

        # Numbers
        if ch.isdigit():
            start = i
            i += 1
            while i < n and (sql[i].isdigit() or sql[i] == "."):
                i += 1
            tokens.append(Token("NUMBER", sql[start:i], start, i))
            continue

        # Words / keywords / unquoted identifiers
        if ch.isalpha() or ch in ("_", "$", "@"):
            start = i
            i += 1
            while i < n and (sql[i].isalnum() or sql[i] in ("_", "$")):
                i += 1
            tokens.append(Token("WORD", sql[start:i], start, i))
            continue

        # Operators / other single chars
        start = i
        i += 1
        while i < n and sql[i] in "=<>!+-*/%&|^~:":
            i += 1
        tokens.append(Token("OP", sql[start:i], start, i))

    return tokens


def split_statements(sql: str) -> list[str]:
    """Split a SQL script on top-level semicolons, ignoring empty statements."""
    tokens = tokenize(sql)
    statements: list[str] = []
    start_offset = 0
    depth = 0

    for tok in tokens:
        if tok.kind == "SYMBOL":
            if tok.text == "(":
                depth += 1
            elif tok.text == ")" and depth > 0:
                depth -= 1
            elif tok.text == ";" and depth == 0:
                piece = sql[start_offset : tok.start].strip()
                if piece:
                    statements.append(piece)
                start_offset = tok.end

    tail = sql[start_offset:].strip()
    if tail:
        statements.append(tail)
    return statements


def _parse_qualified_name(tokens: list[Token], idx: int) -> tuple[str | None, str | None, int]:
    """Parse `[schema.]table` starting at `idx`. Returns (schema, table, next_idx)."""
    if idx >= len(tokens):
        return None, None, idx
    t0 = tokens[idx]
    if t0.kind not in ("WORD", "IDENT"):
        return None, None, idx
    first = unquote_ident(t0.text)
    if (
        idx + 2 < len(tokens)
        and tokens[idx + 1].kind == "SYMBOL"
        and tokens[idx + 1].text == "."
        and tokens[idx + 2].kind in ("WORD", "IDENT")
    ):
        second = unquote_ident(tokens[idx + 2].text)
        return first, second, idx + 3
    return None, first, idx + 1


def _has_top_level_keyword(tokens: list[Token], keyword: str) -> bool:
    depth = 0
    target = keyword.upper()
    for tok in tokens:
        if tok.kind == "SYMBOL":
            if tok.text == "(":
                depth += 1
            elif tok.text == ")" and depth > 0:
                depth -= 1
        elif depth == 0 and tok.kind == "WORD" and tok.upper == target:
            return True
    return False


def _extract_where_clause(sql: str, tokens: list[Token], start_idx: int) -> str | None:
    """Extract raw SQL of top-level WHERE clause up to ORDER BY / LIMIT / RETURNING / end."""
    depth = 0
    where_tok_idx: int | None = None

    for i in range(start_idx, len(tokens)):
        tok = tokens[i]
        if tok.kind == "SYMBOL":
            if tok.text == "(":
                depth += 1
            elif tok.text == ")" and depth > 0:
                depth -= 1
        elif depth == 0 and tok.kind == "WORD":
            if tok.upper == "WHERE" and where_tok_idx is None:
                where_tok_idx = i
                break

    if where_tok_idx is None or where_tok_idx + 1 >= len(tokens):
        return None

    where_start = tokens[where_tok_idx + 1].start
    where_end = len(sql)
    depth = 0

    for i in range(where_tok_idx + 1, len(tokens)):
        tok = tokens[i]
        if tok.kind == "SYMBOL":
            if tok.text == "(":
                depth += 1
            elif tok.text == ")" and depth > 0:
                depth -= 1
            elif tok.text == ";" and depth == 0:
                where_end = tok.start
                break
        elif depth == 0 and tok.kind == "WORD":
            if tok.upper in ("LIMIT", "RETURNING", "FOR", "GROUP", "HAVING"):
                where_end = tok.start
                break
            if (
                tok.upper == "ORDER"
                and i + 1 < len(tokens)
                and tokens[i + 1].kind == "WORD"
                and tokens[i + 1].upper == "BY"
            ):
                where_end = tok.start
                break

    clause = sql[where_start:where_end].strip()
    return clause or None


def _extract_alias(tokens: list[Token], idx: int, stop_keywords: set[str]) -> tuple[str | None, int]:
    if idx >= len(tokens):
        return None, idx
    tok = tokens[idx]
    if tok.kind == "WORD" and tok.upper == "AS" and idx + 1 < len(tokens):
        nxt = tokens[idx + 1]
        if nxt.kind in ("WORD", "IDENT"):
            return unquote_ident(nxt.text), idx + 2
    if tok.kind in ("WORD", "IDENT"):
        if tok.kind == "WORD" and tok.upper in stop_keywords:
            return None, idx
        return unquote_ident(tok.text), idx + 1
    return None, idx


def _extract_top_level_slice(
    sql: str,
    tokens: list[Token],
    start_idx: int,
    start_keyword: str,
    stop_keywords: set[str],
) -> str | None:
    depth = 0
    kw_idx: int | None = None
    target = start_keyword.upper()
    for i in range(start_idx, len(tokens)):
        tok = tokens[i]
        if tok.kind == "SYMBOL":
            if tok.text == "(":
                depth += 1
            elif tok.text == ")" and depth > 0:
                depth -= 1
        elif depth == 0 and tok.kind == "WORD" and tok.upper == target:
            kw_idx = i
            break
    if kw_idx is None or kw_idx + 1 >= len(tokens):
        return None
    slice_start = tokens[kw_idx + 1].start
    slice_end = len(sql)
    depth = 0
    for i in range(kw_idx + 1, len(tokens)):
        tok = tokens[i]
        if tok.kind == "SYMBOL":
            if tok.text == "(":
                depth += 1
            elif tok.text == ")" and depth > 0:
                depth -= 1
            elif tok.text == ";" and depth == 0:
                slice_end = tok.start
                break
        elif depth == 0 and tok.kind == "WORD" and tok.upper in stop_keywords:
            slice_end = tok.start
            break
    part = sql[slice_start:slice_end].strip()
    return part or None


_NON_COLUMN_ALTER_TARGETS = frozenset(
    {
        "CONSTRAINT",
        "PRIMARY",
        "UNIQUE",
        "FOREIGN",
        "CHECK",
        "INDEX",
        "KEY",
        "FULLTEXT",
        "SPATIAL",
        "PARTITION",
        "DEFAULT",
    }
)


def _parse_alter_table_actions(tokens: list[Token], start_idx: int) -> list[dict[str, Any]] | None:
    """Parse reversible ALTER TABLE sub-clauses (ADD/DROP/RENAME COLUMN, RENAME TO)."""
    rem = tokens[start_idx:]
    if rem and rem[-1].kind == "SYMBOL" and rem[-1].text == ";":
        rem = rem[:-1]
    if not rem:
        return None

    clauses: list[list[Token]] = []
    cur: list[Token] = []
    depth = 0
    for tok in rem:
        if tok.kind == "SYMBOL":
            if tok.text == "(":
                depth += 1
            elif tok.text == ")" and depth > 0:
                depth -= 1
            elif tok.text == "," and depth == 0:
                if cur:
                    clauses.append(cur)
                    cur = []
                continue
        cur.append(tok)
    if cur:
        clauses.append(cur)
    if not clauses:
        return None

    actions: list[dict[str, Any]] = []
    for ctoks in clauses:
        kw = ctoks[0].upper if ctoks[0].kind == "WORD" else ""
        if kw == "ADD":
            if len(ctoks) < 2:
                return None
            cidx = 1
            if ctoks[cidx].upper == "COLUMN":
                cidx += 1
            elif ctoks[cidx].upper in _NON_COLUMN_ALTER_TARGETS:
                return None
            if_not_exists = False
            if (
                cidx + 2 < len(ctoks)
                and ctoks[cidx].upper == "IF"
                and ctoks[cidx + 1].upper == "NOT"
                and ctoks[cidx + 2].upper == "EXISTS"
            ):
                if_not_exists = True
                cidx += 3
            if cidx >= len(ctoks) or ctoks[cidx].kind not in ("WORD", "IDENT"):
                return None
            actions.append(
                {
                    "action": "ADD_COLUMN",
                    "column": unquote_ident(ctoks[cidx].text),
                    "if_not_exists": if_not_exists,
                }
            )
            continue

        if kw == "DROP":
            if len(ctoks) < 2:
                return None
            cidx = 1
            if ctoks[cidx].upper == "COLUMN":
                cidx += 1
            elif ctoks[cidx].upper in _NON_COLUMN_ALTER_TARGETS:
                return None
            if_exists = False
            if (
                cidx + 1 < len(ctoks)
                and ctoks[cidx].upper == "IF"
                and ctoks[cidx + 1].upper == "EXISTS"
            ):
                if_exists = True
                cidx += 2
            if cidx >= len(ctoks) or ctoks[cidx].kind not in ("WORD", "IDENT"):
                return None
            actions.append(
                {
                    "action": "DROP_COLUMN",
                    "column": unquote_ident(ctoks[cidx].text),
                    "if_exists": if_exists,
                }
            )
            continue

        if kw == "RENAME":
            if len(ctoks) < 2:
                return None
            if ctoks[1].upper == "COLUMN":
                if len(ctoks) >= 5 and ctoks[3].upper == "TO":
                    actions.append(
                        {
                            "action": "RENAME_COLUMN",
                            "old_name": unquote_ident(ctoks[2].text),
                            "new_name": unquote_ident(ctoks[4].text),
                        }
                    )
                    continue
                return None
            if ctoks[1].upper in _NON_COLUMN_ALTER_TARGETS or ctoks[1].upper in ("INDEX", "KEY"):
                return None
            tidx = 2 if ctoks[1].upper in ("TO", "AS") else 1
            new_schema, new_table, _ = _parse_qualified_name(ctoks, tidx)
            if not new_table:
                return None
            actions.append(
                {
                    "action": "RENAME_TABLE",
                    "new_schema": new_schema,
                    "new_table": new_table,
                }
            )
            continue

        if kw == "ALTER":
            cidx = 2 if len(ctoks) >= 3 and ctoks[1].upper == "COLUMN" else 1
            if cidx + 1 >= len(ctoks) or ctoks[cidx].kind not in ("WORD", "IDENT"):
                return None
            col = unquote_ident(ctoks[cidx].text)
            rest_words = [t.upper for t in ctoks[cidx + 1 :] if t.kind == "WORD"]
            if (rest_words and rest_words[0] == "TYPE") or rest_words[:3] == ["SET", "DATA", "TYPE"]:
                actions.append({"action": "ALTER_COLUMN_TYPE", "column": col})
                continue
            if rest_words[:2] in (["SET", "DEFAULT"], ["DROP", "DEFAULT"]):
                actions.append({"action": "ALTER_COLUMN_DEFAULT", "column": col})
                continue
            if rest_words[:3] in (["SET", "NOT", "NULL"], ["DROP", "NOT", "NULL"]):
                actions.append({"action": "ALTER_COLUMN_NOT_NULL", "column": col})
                continue
            return None

        if kw == "MODIFY":
            cidx = 2 if len(ctoks) >= 3 and ctoks[1].upper == "COLUMN" else 1
            if cidx >= len(ctoks) or ctoks[cidx].kind not in ("WORD", "IDENT"):
                return None
            actions.append({"action": "MODIFY_COLUMN", "column": unquote_ident(ctoks[cidx].text)})
            continue

        if kw == "CHANGE":
            cidx = 2 if len(ctoks) >= 4 and ctoks[1].upper == "COLUMN" else 1
            if cidx + 1 >= len(ctoks) or ctoks[cidx].kind not in ("WORD", "IDENT") or ctoks[cidx + 1].kind not in ("WORD", "IDENT"):
                return None
            actions.append(
                {
                    "action": "CHANGE_COLUMN",
                    "old_name": unquote_ident(ctoks[cidx].text),
                    "new_name": unquote_ident(ctoks[cidx + 1].text),
                }
            )
            continue

        return None

    return actions


def parse_statement(sql: str) -> ParsedStatement:
    """Parse a single SQL statement into a ParsedStatement."""
    raw = sql.strip()
    tokens = tokenize(raw)
    if not tokens:
        return ParsedStatement(raw_sql=raw, kind=StatementKind.OTHER)

    first = tokens[0].upper if tokens[0].kind == "WORD" else ""
    second = tokens[1].upper if len(tokens) > 1 and tokens[1].kind == "WORD" else ""

    # 1. Proxy control commands: PROXY HISTORY | PROXY REVERSE <id> [DRY RUN] [FORCE] | PROXY DIFF <id>
    if first == "PROXY":
        if second == "HISTORY":
            limit = 25
            for i in range(2, len(tokens) - 1):
                if tokens[i].upper == "LIMIT" and tokens[i + 1].kind == "NUMBER":
                    limit = int(tokens[i + 1].text)
            return ParsedStatement(
                raw_sql=raw,
                kind=StatementKind.PROXY_HISTORY,
                proxy_limit=limit,
            )
        ptokens = (
            tokens[:-1]
            if tokens and tokens[-1].text == ";"
            else tokens
        )
        if second == "REVERSE":
            if len(ptokens) == 2 or (
                ptokens[2].kind == "WORD"
                and ptokens[2].upper in ("DRY", "DRY_RUN", "FORCE", "CASCADE")
            ):
                tx_id = "LAST"
                end_idx = 2
            else:
                arg_idx = 2
                end_idx = arg_idx + 1
                while end_idx < len(ptokens) and ptokens[end_idx].start == ptokens[end_idx - 1].end:
                    end_idx += 1
                raw_arg = raw[ptokens[arg_idx].start : ptokens[end_idx - 1].end]
                tx_id = unquote_ident(raw_arg.strip("'"))
            words = {t.upper for t in ptokens[end_idx:] if t.kind == "WORD"}
            dry_run = ("DRY" in words and "RUN" in words) or ("DRY_RUN" in words)
            force = "FORCE" in words
            cascade = "CASCADE" in words
            return ParsedStatement(
                raw_sql=raw,
                kind=StatementKind.PROXY_REVERSE,
                proxy_tx_id=tx_id,
                proxy_dry_run=dry_run,
                proxy_force=force,
                proxy_cascade=cascade,
            )
        if second == "DIFF":
            if len(ptokens) == 2:
                tx_id = "LAST"
            else:
                arg_idx = 2
                end_idx = arg_idx + 1
                while end_idx < len(ptokens) and ptokens[end_idx].start == ptokens[end_idx - 1].end:
                    end_idx += 1
                raw_arg = raw[ptokens[arg_idx].start : ptokens[end_idx - 1].end]
                tx_id = unquote_ident(raw_arg.strip("'"))
            return ParsedStatement(
                raw_sql=raw,
                kind=StatementKind.PROXY_DIFF,
                proxy_tx_id=tx_id,
            )
        if second == "PURGE":
            if len(ptokens) == 2:
                return ParsedStatement(raw_sql=raw, kind=StatementKind.PROXY_PURGE)
            mode_kw = ptokens[2].upper
            if mode_kw == "LOG":
                limit = 50
                for i in range(3, len(ptokens) - 1):
                    if ptokens[i].upper == "LIMIT" and ptokens[i + 1].kind == "NUMBER":
                        limit = int(ptokens[i + 1].text)
                if len(ptokens) == 4 and ptokens[3].kind == "NUMBER":
                    limit = int(ptokens[3].text)
                return ParsedStatement(
                    raw_sql=raw,
                    kind=StatementKind.PROXY_PURGE,
                    purge_mode="log",
                    proxy_limit=limit,
                )
            if mode_kw in ("TX", "TRANSACTION") and len(ptokens) >= 4:
                raw_tx = raw[ptokens[3].start : ptokens[-1].end]
                return ParsedStatement(
                    raw_sql=raw,
                    kind=StatementKind.PROXY_PURGE,
                    purge_mode="tx",
                    purge_target=unquote_ident(raw_tx.strip("'")),
                )
            if mode_kw == "TABLE" and len(ptokens) >= 4:
                tbl = unquote_ident(ptokens[-1].text.strip("'"))
                return ParsedStatement(
                    raw_sql=raw,
                    kind=StatementKind.PROXY_PURGE,
                    purge_mode="table",
                    purge_target=tbl,
                )
            if mode_kw == "OLDER" and len(ptokens) >= 5 and ptokens[3].upper == "THAN":
                num_str = ptokens[4].text.strip("'").rstrip("dD")
                return ParsedStatement(
                    raw_sql=raw,
                    kind=StatementKind.PROXY_PURGE,
                    purge_mode="older_than",
                    purge_days=float(num_str),
                )
            return ParsedStatement(raw_sql=raw, kind=StatementKind.PROXY_PURGE)

    # 2. Transaction control
    if first == "BEGIN" or (first == "START" and second == "TRANSACTION"):
        return ParsedStatement(raw_sql=raw, kind=StatementKind.TX_BEGIN)
    if first in ("COMMIT", "END"):
        return ParsedStatement(raw_sql=raw, kind=StatementKind.TX_COMMIT)
    if first == "SAVEPOINT" and len(tokens) >= 2:
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.SAVEPOINT,
            savepoint_name=unquote_ident(tokens[1].text),
        )
    if first == "RELEASE" and len(tokens) >= 2:
        sp_idx = 2 if second == "SAVEPOINT" and len(tokens) >= 3 else 1
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.RELEASE_SAVEPOINT,
            savepoint_name=unquote_ident(tokens[sp_idx].text),
        )
    if first == "ROLLBACK":
        if second == "TO":
            sp_idx = 3 if len(tokens) > 3 and tokens[2].upper == "SAVEPOINT" else 2
            sp_name = unquote_ident(tokens[sp_idx].text) if sp_idx < len(tokens) else None
            return ParsedStatement(
                raw_sql=raw,
                kind=StatementKind.ROLLBACK_TO_SAVEPOINT,
                savepoint_name=sp_name,
            )
        return ParsedStatement(raw_sql=raw, kind=StatementKind.TX_ROLLBACK)

    # 3. Read-only statements
    if first in ("SELECT", "WITH", "EXPLAIN", "PRAGMA", "SHOW", "DESCRIBE", "DESC"):
        return ParsedStatement(raw_sql=raw, kind=StatementKind.SELECT)

    has_returning = _has_top_level_keyword(tokens, "RETURNING")

    # 4. INSERT / REPLACE
    if first in ("INSERT", "REPLACE"):
        idx = 1
        has_or_replace = False
        if first == "INSERT" and idx + 1 < len(tokens) and tokens[idx].upper == "OR" and tokens[idx + 1].upper == "REPLACE":
            has_or_replace = True
        # Handle INSERT [OR REPLACE|ABORT|IGNORE...] INTO [schema.]table or REPLACE [INTO] [schema.]table
        while idx < len(tokens) and tokens[idx].upper != "INTO":
            if first == "REPLACE" and tokens[idx].kind in ("WORD", "IDENT") and tokens[idx].upper not in ("LOW_PRIORITY", "DELAYED"):
                break
            idx += 1
        if idx < len(tokens) and tokens[idx].upper == "INTO":
            idx += 1
        schema, table, _ = _parse_qualified_name(tokens, idx)
        is_upsert = (
            first == "REPLACE"
            or has_or_replace
            or _has_top_level_keyword(tokens, "CONFLICT")
            or _has_top_level_keyword(tokens, "DUPLICATE")
        )
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.INSERT,
            schema=schema,
            table=table,
            has_returning=has_returning,
            is_upsert=is_upsert,
        )

    # 5. UPDATE
    if first == "UPDATE":
        idx = 1
        if idx < len(tokens) and tokens[idx].upper == "OR":
            idx += 2  # skip OR <conflict_action>
        schema, table, next_idx = _parse_qualified_name(tokens, idx)
        join_kws = {"SET", "WHERE", "FROM", "JOIN", "INNER", "LEFT", "RIGHT", "CROSS", "STRAIGHT_JOIN"}
        alias, after_alias_idx = _extract_alias(tokens, next_idx, join_kws)

        # Check MySQL-style JOINs before SET: UPDATE t1 a1 JOIN t2 a2 ON ... SET ...
        from_join_clause: str | None = None
        depth = 0
        set_idx: int | None = None
        for i in range(after_alias_idx, len(tokens)):
            t = tokens[i]
            if t.kind == "SYMBOL":
                if t.text == "(":
                    depth += 1
                elif t.text == ")" and depth > 0:
                    depth -= 1
            elif depth == 0 and t.kind == "WORD" and t.upper == "SET":
                set_idx = i
                break
        if set_idx is not None and set_idx > after_alias_idx:
            join_slice = raw[tokens[after_alias_idx].start : tokens[set_idx].start].strip()
            if join_slice:
                from_join_clause = join_slice

        # Check Postgres/SQLite-style UPDATE ... SET ... FROM ... WHERE ...
        if from_join_clause is None and set_idx is not None:
            pg_from = _extract_top_level_slice(
                raw, tokens, set_idx + 1, "FROM", {"WHERE", "RETURNING", "ORDER", "LIMIT"}
            )
            if pg_from:
                from_join_clause = pg_from

        where_clause = _extract_where_clause(raw, tokens, next_idx)
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.UPDATE,
            schema=schema,
            table=table,
            alias=alias,
            from_join_clause=from_join_clause,
            where_clause=where_clause,
            has_returning=has_returning,
        )

    # 6. DELETE (standard DELETE FROM ... [USING ...], and MySQL DELETE target FROM target JOIN ...)
    if first == "DELETE":
        idx = 1
        if idx < len(tokens) and tokens[idx].upper == "FROM":
            idx += 1
            schema, table, next_idx = _parse_qualified_name(tokens, idx)
            alias, after_alias_idx = _extract_alias(
                tokens, next_idx, {"WHERE", "ORDER", "LIMIT", "RETURNING", "USING", "JOIN", "INNER", "LEFT", "RIGHT"}
            )
            using_clause = _extract_top_level_slice(
                raw, tokens, next_idx, "USING", {"WHERE", "ORDER", "LIMIT", "RETURNING"}
            )
            from_join_clause = using_clause
            # Also handle DELETE FROM t USING t JOIN other ... (MySQL multi-table DELETE FROM ... USING ...)
            if using_clause is None and after_alias_idx < len(tokens):
                # Check if JOIN directly follows
                if tokens[after_alias_idx].kind == "WORD" and tokens[after_alias_idx].upper in (
                    "JOIN", "INNER", "LEFT", "RIGHT", "CROSS", "STRAIGHT_JOIN"
                ):
                    from_join_clause = _extract_top_level_slice(
                        raw, tokens, after_alias_idx - 1, tokens[after_alias_idx - 1].text, {"WHERE", "ORDER", "LIMIT"}
                    )
            where_clause = _extract_where_clause(raw, tokens, next_idx)
            return ParsedStatement(
                raw_sql=raw,
                kind=StatementKind.DELETE,
                schema=schema,
                table=table,
                alias=alias,
                from_join_clause=from_join_clause,
                where_clause=where_clause,
                has_returning=has_returning,
            )

        # MySQL multi-table syntax: DELETE t1 FROM tbl1 [AS t1] JOIN tbl2 [AS t2] ON ... [WHERE ...]
        target_tok = tokens[idx] if idx < len(tokens) else None
        target_ref = unquote_ident(target_tok.text) if target_tok else None
        while idx < len(tokens) and tokens[idx].upper != "FROM":
            idx += 1
        if idx < len(tokens) and tokens[idx].upper == "FROM":
            idx += 1
        schema, table, next_idx = _parse_qualified_name(tokens, idx)
        alias, after_alias_idx = _extract_alias(
            tokens, next_idx, {"JOIN", "INNER", "LEFT", "RIGHT", "CROSS", "STRAIGHT_JOIN", "WHERE", "ORDER", "LIMIT"}
        )
        if alias is None and target_ref and target_ref != table:
            alias = target_ref
        # Capture JOIN clause between after_alias_idx and WHERE / ORDER / LIMIT / ;
        join_end = len(raw)
        depth = 0
        for i in range(after_alias_idx, len(tokens)):
            t = tokens[i]
            if t.kind == "SYMBOL":
                if t.text == "(":
                    depth += 1
                elif t.text == ")" and depth > 0:
                    depth -= 1
                elif t.text == ";" and depth == 0:
                    join_end = t.start
                    break
            elif depth == 0 and t.kind == "WORD" and t.upper in ("WHERE", "ORDER", "LIMIT"):
                join_end = t.start
                break
        from_join_clause = (
            raw[tokens[after_alias_idx].start : join_end].strip()
            if after_alias_idx < len(tokens) and tokens[after_alias_idx].start < join_end
            else None
        )
        where_clause = _extract_where_clause(raw, tokens, next_idx)
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.DELETE,
            schema=schema,
            table=table,
            alias=alias,
            from_join_clause=from_join_clause or None,
            where_clause=where_clause,
            has_returning=has_returning,
        )

    # 6b. MERGE INTO [schema.]table [AS alias] USING <src> ON <cond> WHEN ...
    if first == "MERGE":
        idx = 1
        if idx < len(tokens) and tokens[idx].upper == "INTO":
            idx += 1
        schema, table, next_idx = _parse_qualified_name(tokens, idx)
        alias, after_alias_idx = _extract_alias(tokens, next_idx, {"USING"})
        merge_using = _extract_top_level_slice(raw, tokens, after_alias_idx, "USING", {"ON"})
        merge_on = _extract_top_level_slice(raw, tokens, after_alias_idx, "ON", {"WHEN"})
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.MERGE,
            schema=schema,
            table=table,
            alias=alias,
            merge_using=merge_using,
            merge_on=merge_on,
        )

    # 7. DROP TABLE [IF EXISTS] [schema.]t1 [, [schema.]t2 ...] [CASCADE|RESTRICT]
    if first == "DROP" and second == "TABLE":
        idx = 2
        if_exists = False
        if (
            idx + 1 < len(tokens)
            and tokens[idx].upper == "IF"
            and tokens[idx + 1].upper == "EXISTS"
        ):
            if_exists = True
            idx += 2
        targets: list[tuple[str | None, str]] = []
        while idx < len(tokens):
            if tokens[idx].kind == "SYMBOL" and tokens[idx].text == ";":
                break
            if tokens[idx].kind == "WORD" and tokens[idx].upper in ("CASCADE", "RESTRICT"):
                break
            sch, tbl, next_idx = _parse_qualified_name(tokens, idx)
            if not tbl:
                break
            targets.append((sch, tbl))
            idx = next_idx
            if idx < len(tokens) and tokens[idx].kind == "SYMBOL" and tokens[idx].text == ",":
                idx += 1
                continue
            break
        schema, table = targets[0] if targets else (None, None)
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.DROP_TABLE,
            schema=schema,
            table=table,
            drop_targets=targets,
            if_exists=if_exists,
        )

    # 8. TRUNCATE [TABLE] [schema.]t1 [, [schema.]t2 ...]
    if first == "TRUNCATE":
        idx = 2 if second == "TABLE" else 1
        targets = []
        while idx < len(tokens):
            if tokens[idx].kind == "SYMBOL" and tokens[idx].text == ";":
                break
            if tokens[idx].kind == "WORD" and tokens[idx].upper in ("CASCADE", "RESTRICT", "RESTART", "CONTINUE", "IDENTITY"):
                break
            sch, tbl, next_idx = _parse_qualified_name(tokens, idx)
            if not tbl:
                break
            targets.append((sch, tbl))
            idx = next_idx
            if idx < len(tokens) and tokens[idx].kind == "SYMBOL" and tokens[idx].text == ",":
                idx += 1
                continue
            break
        schema, table = targets[0] if targets else (None, None)
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.TRUNCATE_TABLE,
            schema=schema,
            table=table,
            drop_targets=targets,
        )

    # 8b. CREATE [UNIQUE] INDEX [CONCURRENTLY] [IF NOT EXISTS] [schema.]idx ON [schema.]table (...)
    if first == "CREATE" and (
        second == "INDEX"
        or (second == "UNIQUE" and len(tokens) > 2 and tokens[2].upper == "INDEX")
    ):
        idx = 3 if second == "UNIQUE" else 2
        if idx < len(tokens) and tokens[idx].upper == "CONCURRENTLY":
            idx += 1
        if (
            idx + 2 < len(tokens)
            and tokens[idx].upper == "IF"
            and tokens[idx + 1].upper == "NOT"
            and tokens[idx + 2].upper == "EXISTS"
        ):
            idx += 3
        idx_schema, idx_name, next_idx = _parse_qualified_name(tokens, idx)
        tbl_schema: str | None = None
        tbl_name: str | None = None
        for k in range(next_idx, len(tokens)):
            if tokens[k].kind == "WORD" and tokens[k].upper == "ON" and k + 1 < len(tokens):
                tbl_schema, tbl_name, _ = _parse_qualified_name(tokens, k + 1)
                break
        if idx_name and tbl_name:
            return ParsedStatement(
                raw_sql=raw,
                kind=StatementKind.CREATE_INDEX,
                schema=idx_schema or tbl_schema,
                table=tbl_name,
                index_name=idx_name,
            )

    # 8c. DROP INDEX [CONCURRENTLY] [IF EXISTS] [schema.]idx [ON [schema.]table]
    if first == "DROP" and second == "INDEX":
        idx = 2
        if idx < len(tokens) and tokens[idx].upper == "CONCURRENTLY":
            idx += 1
        if_exists = False
        if (
            idx + 1 < len(tokens)
            and tokens[idx].upper == "IF"
            and tokens[idx + 1].upper == "EXISTS"
        ):
            if_exists = True
            idx += 2
        idx_schema, idx_name, next_idx = _parse_qualified_name(tokens, idx)
        tbl_schema = None
        tbl_name = None
        for k in range(next_idx, len(tokens)):
            if tokens[k].kind == "WORD" and tokens[k].upper == "ON" and k + 1 < len(tokens):
                tbl_schema, tbl_name, _ = _parse_qualified_name(tokens, k + 1)
                break
        if idx_name:
            return ParsedStatement(
                raw_sql=raw,
                kind=StatementKind.DROP_INDEX,
                schema=idx_schema or tbl_schema,
                table=tbl_name,
                index_name=idx_name,
                if_exists=if_exists,
            )

    # 9. Reversible ALTER TABLE / RENAME TABLE
    if first == "ALTER" and second == "TABLE":
        idx = 2
        if (
            idx + 1 < len(tokens)
            and tokens[idx].upper == "IF"
            and tokens[idx + 1].upper == "EXISTS"
        ):
            idx += 2
        schema, table, idx = _parse_qualified_name(tokens, idx)
        actions = _parse_alter_table_actions(tokens, idx)
        if table and actions:
            return ParsedStatement(
                raw_sql=raw,
                kind=StatementKind.ALTER_TABLE,
                schema=schema,
                table=table,
                alter_actions=actions,
            )

    if first == "RENAME" and second == "TABLE":
        # Single-table RENAME TABLE [schema.]old TO [new_schema.]new
        has_comma = any(t.kind == "SYMBOL" and t.text == "," for t in tokens[2:])
        if not has_comma:
            old_schema, old_table, next_idx = _parse_qualified_name(tokens, 2)
            if old_table and next_idx < len(tokens) and tokens[next_idx].upper == "TO":
                new_schema, new_table, _ = _parse_qualified_name(tokens, next_idx + 1)
                if new_table:
                    return ParsedStatement(
                        raw_sql=raw,
                        kind=StatementKind.ALTER_TABLE,
                        schema=old_schema,
                        table=old_table,
                        alter_actions=[
                            {
                                "action": "RENAME_TABLE",
                                "new_schema": new_schema,
                                "new_table": new_table,
                            }
                        ],
                    )

    # 10. Other DDL
    if first in ("CREATE", "ALTER", "RENAME", "GRANT", "REVOKE"):
        return ParsedStatement(
            raw_sql=raw,
            kind=StatementKind.OTHER_DDL,
            warnings=[f"{first} statement is not automatically reversible."],
        )

    return ParsedStatement(raw_sql=raw, kind=StatementKind.OTHER)


def extract_insert_value_dicts(
    sql: str,
    table_columns: list[str],
    params: tuple[Any, ...] | list[Any] = (),
) -> list[dict[str, Any]] | None:
    """
    Extract literal/bound row dicts from `INSERT INTO tbl [(cols)] VALUES (...), (...)`.
    Returns None if the statement uses `INSERT ... SELECT` or non-literal expressions.
    """
    tokens = tokenize(sql)
    upper_words = [t.upper if t.kind == "WORD" else "" for t in tokens]
    if "VALUES" not in upper_words:
        return None
    val_idx = upper_words.index("VALUES")

    col_list: list[str] | None = None
    for i in range(val_idx):
        if tokens[i].kind == "SYMBOL" and tokens[i].text == "(":
            cols: list[str] = []
            j = i + 1
            while j < val_idx and not (tokens[j].kind == "SYMBOL" and tokens[j].text == ")"):
                if tokens[j].kind in ("WORD", "IDENT"):
                    cols.append(unquote_ident(tokens[j].text))
                j += 1
            col_list = cols
            break

    target_cols = col_list if col_list is not None else table_columns
    rows: list[dict[str, Any]] = []
    param_cursor = 0
    i = val_idx + 1

    while i < len(tokens):
        tok = tokens[i]
        # Stop before ON CONFLICT / ON DUPLICATE / RETURNING
        if tok.kind == "WORD" and tok.upper in ("ON", "RETURNING"):
            break
        if tok.kind == "SYMBOL" and tok.text == "(":
            i += 1
            tuple_vals: list[Any] = []
            while i < len(tokens):
                t = tokens[i]
                if t.kind == "SYMBOL" and t.text == ")":
                    i += 1
                    break
                if t.kind == "SYMBOL" and t.text == ",":
                    i += 1
                    continue
                if t.kind == "OP" and t.text == "?" and param_cursor < len(params):
                    tuple_vals.append(params[param_cursor])
                    param_cursor += 1
                elif (
                    t.kind == "WORD"
                    and t.text.startswith("$")
                    and t.text[1:].isdigit()
                    and 1 <= int(t.text[1:]) <= len(params)
                ):
                    tuple_vals.append(params[int(t.text[1:]) - 1])
                elif (
                    t.kind == "OP"
                    and t.text == "?"
                    and i + 1 < len(tokens)
                    and tokens[i + 1].kind == "NUMBER"
                    and tokens[i + 1].start == t.end
                ):
                    pnum = int(tokens[i + 1].text)
                    if 1 <= pnum <= len(params):
                        tuple_vals.append(params[pnum - 1])
                        i += 1
                    else:
                        return None
                elif t.kind == "NUMBER":
                    tuple_vals.append(float(t.text) if "." in t.text else int(t.text))
                elif t.kind == "STRING":
                    tuple_vals.append(t.text[1:-1].replace("''", "'").replace("\\'", "'"))
                elif t.kind == "WORD" and t.upper == "NULL":
                    tuple_vals.append(None)
                elif t.kind == "WORD" and t.upper in ("TRUE", "FALSE"):
                    tuple_vals.append(t.upper == "TRUE")
                else:
                    return None
                i += 1
            if len(tuple_vals) != len(target_cols):
                return None
            rows.append(dict(zip(target_cols, tuple_vals)))
        else:
            i += 1

    return rows or None
