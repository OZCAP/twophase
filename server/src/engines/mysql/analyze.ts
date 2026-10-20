import { OPERATION_RANK, type Access, type Analysis, type Operation, type StatementAnalysis, type Verb } from '../types.js';
import { classifyFunction, type RoutineCatalog } from './functions.js';
import { LexError, lex, sliceTokens, type LexOptions, type Token } from './lexer.js';

/**
 * Classifies MySQL / MariaDB SQL from its tokens. Same principles as the Postgres analyzer:
 *  - Anything we don't recognise is `admin` (denied by default). Unknown never means "read".
 *  - A statement's kind is the strictest of everything it does: row locks, side-effecting and
 *    stored functions, what EXPLAIN ANALYZE would execute, what a prepared statement contains.
 * Table names are lowercased (MySQL may be case-insensitive about them) and names qualified with
 * the current database are reported bare, so a rule on `orders` also covers `shop.Orders`.
 */

export interface MysqlAnalyzeContext extends LexOptions {
  /** The session's current database (the real name upstream). */
  database?: string | null;
  /** Other names that mean the current database (the proxy slug clients connect with). */
  databaseAliases?: string[];
  catalog?: RoutineCatalog | null;
  /** Statements prepared earlier in this session (PREPARE name FROM '…'), for EXECUTE. */
  prepared?: Map<string, StatementAnalysis>;
}

type Partial = Omit<StatementAnalysis, 'text'>;

/** Session variables a client may set. Everything else (sql_mode, sql_log_bin, foreign_key_checks, …) is admin. */
const SESSION_VARIABLES = new Set([
  'autocommit',
  'time_zone',
  'sql_select_limit',
  'sql_safe_updates',
  'sql_notes',
  'sql_warnings',
  'sql_quote_show_create',
  'sql_auto_is_null',
  'sql_big_selects',
  'sql_buffer_result',
  'max_execution_time',
  'max_statement_time',
  'lock_wait_timeout',
  'innodb_lock_wait_timeout',
  'wait_timeout',
  'interactive_timeout',
  'net_read_timeout',
  'net_write_timeout',
  'group_concat_max_len',
  'transaction_isolation',
  'tx_isolation',
  'transaction_read_only',
  'tx_read_only',
  'character_set_client',
  'character_set_connection',
  'character_set_results',
  'collation_connection',
  'session_track_schema',
  'session_track_state_change',
  'session_track_system_variables',
  'session_track_transaction_info',
  'session_track_gtids',
  'profiling',
  'profiling_history_size',
  'div_precision_increment',
  'default_week_format',
  'lc_time_names',
  'lc_messages',
  'max_sort_length',
  'max_join_size',
  'sort_buffer_size',
  'join_buffer_size',
  'tmp_table_size',
  'max_heap_table_size',
  'big_tables',
  'cte_max_recursion_depth',
  'information_schema_stats_expiry',
  'end_markers_in_json',
  'eq_range_index_dive_limit',
  'optimizer_search_depth',
  'block_encryption_mode',
  'completion_type',
  'resultset_metadata',
]);

const CHARSET_VARIABLES = new Set(['character_set_client', 'character_set_connection', 'character_set_results', 'collation_connection']);

/**
 * Character sets whose multibyte characters can't hide an ASCII quote or backslash from a lexer
 * that reads the bytes as UTF-8. (big5, sjis, gbk, cp932, gb18030 can, so they are refused.)
 */
export const SAFE_CHARSETS = /^(utf8|utf8mb3|utf8mb4|latin1|ascii|binary|default|null)(_[a-z0-9_]+)?$/;

/** Words that end a table reference (can't be an unquoted alias). */
const RESERVED = new Set(
  `SELECT FROM WHERE JOIN INNER LEFT RIGHT CROSS NATURAL STRAIGHT_JOIN OUTER FULL ON USING SET GROUP ORDER BY LIMIT
  HAVING WINDOW UNION EXCEPT INTERSECT FOR LOCK PARTITION USE IGNORE FORCE INTO VALUES VALUE AS AND OR NOT XOR WITH
  LATERAL DUAL WHEN THEN ELSE END CASE IN IS NULL LIKE BETWEEN EXISTS DISTINCT ALL RETURNING OFFSET KEY INDEX TABLE
  UPDATE DELETE INSERT REPLACE LOW_PRIORITY HIGH_PRIORITY DELAYED QUICK INTERVAL DEFAULT DUPLICATE STRAIGHT_JOIN
  READ WRITE NOWAIT SKIP OF SHARE MODE PROCEDURE`
    .split(/\s+/)
    .filter(Boolean),
);

/** Words followed by `(` that are syntax, not function calls. */
const NOT_FUNCTIONS = new Set(
  `IN VALUES VALUE EXISTS AS ON USING JOIN FROM INTO TABLE WHERE AND OR NOT XOR SELECT KEY INDEX PRIMARY UNIQUE OVER
  PARTITION COLUMNS ROW ANY SOME ALL WITH LATERAL RECURSIVE BY THEN ELSE WHEN UNION EXCEPT INTERSECT DISTINCT HAVING
  SET RETURNING LIKE IS BETWEEN REFERENCES CHECK FOREIGN CONSTRAINT AGAINST`
    .split(/\s+/)
    .filter(Boolean),
);

const isPunct = (t: Token | undefined, p: string) => !!t && t.type === 'punct' && t.value === p;
const isWord = (t: Token | undefined, ...words: string[]) => !!t && t.type === 'word' && (words.length === 0 || words.includes(t.upper));
/** An identifier usable as a table or alias: quoted, or an unquoted word that isn't reserved. */
const isName = (t: Token | undefined) => !!t && (t.type === 'ident' || (t.type === 'word' && !RESERVED.has(t.upper)));

function dedupe(accesses: Access[]): Access[] {
  const seen = new Set<string>();
  return accesses.filter((a) => {
    const k = `${a.op}:${a.verb}:${a.table ?? ''}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
}

function kindOf(accesses: Access[]): Operation | 'session' {
  let kind: Operation | null = null;
  for (const a of accesses) if (!kind || OPERATION_RANK[a.op] > OPERATION_RANK[kind]) kind = a.op;
  return kind ?? 'session';
}

const session = (command: string, flags: string[] = []): Partial => ({ command, kind: 'session', accesses: [], flags });
const admin = (command: string, reason: string, extra: Access[] = []): Partial => ({
  command,
  kind: 'admin',
  accesses: dedupe([{ op: 'admin', verb: 'admin', table: null }, ...extra]),
  flags: [reason],
});

interface Ref {
  name: string;
  alias: string | null;
  at: number;
}

/** One statement's tokens, with the bookkeeping shared by every classifier. */
class Stmt {
  /** Token indexes already understood as table names, aliases or syntax (never function calls). */
  consumed = new Set<number>();
  refs: Ref[] = [];
  ctes = new Set<string>();
  flags = new Set<string>();

  constructor(
    readonly t: Token[],
    readonly ctx: MysqlAnalyzeContext,
  ) {
    this.findCtes();
  }

  word(i: number) {
    const tok = this.t[i];
    return tok?.type === 'word' ? tok.upper : null;
  }

  /** Index of the `)` matching the `(` at i (or the end). */
  close(i: number): number {
    let depth = 0;
    for (let j = i; j < this.t.length; j++) {
      if (isPunct(this.t[j], '(')) depth++;
      else if (isPunct(this.t[j], ')') && --depth === 0) return j;
    }
    return this.t.length - 1;
  }

  /** Lowercased, with the current database's qualifier dropped. */
  normalize(name: string): string {
    const lower = name.toLowerCase();
    const dot = lower.indexOf('.');
    if (dot < 0) return lower;
    const db = lower.slice(0, dot);
    const current = [this.ctx.database, ...(this.ctx.databaseAliases ?? [])].filter(Boolean).map((d) => d!.toLowerCase());
    return current.includes(db) ? lower.slice(dot + 1) : lower;
  }

  /** `name` or `db.name` at i. */
  name(i: number): { name: string; next: number } | null {
    if (!isName(this.t[i])) return null;
    let name = this.t[i].value;
    let next = i + 1;
    this.consumed.add(i);
    if (isPunct(this.t[next], '.') && (this.t[next + 1]?.type === 'ident' || this.t[next + 1]?.type === 'word')) {
      name = `${name}.${this.t[next + 1].value}`;
      this.consumed.add(next + 1);
      next += 2;
    }
    return { name, next };
  }

  /** WITH [RECURSIVE] a [(cols)] AS (…), b AS (…): remember the names so they aren't taken for tables. */
  private findCtes() {
    for (let i = 0; i < this.t.length; i++) {
      if (!isWord(this.t[i], 'WITH') || this.t[i + 1]?.upper === 'ROLLUP') continue;
      let j = i + 1;
      if (isWord(this.t[j], 'RECURSIVE')) j++;
      for (;;) {
        if (!isName(this.t[j])) break;
        this.ctes.add(this.t[j].value.toLowerCase());
        this.consumed.add(j);
        j++;
        if (isPunct(this.t[j], '(')) j = this.close(j) + 1;
        if (!isWord(this.t[j], 'AS') || !isPunct(this.t[j + 1], '(')) break;
        j = this.close(j + 1) + 1;
        if (!isPunct(this.t[j], ',')) break;
        j++;
      }
    }
  }

  /**
   * A table reference at i: name, PARTITION (…), [AS] alias, index hints. Returns the index after
   * it, or i unchanged when there is no plain table here (derived table, table function, …).
   */
  ref(i: number, columnsFollow = false): number {
    const tok = this.t[i];
    if (!tok || isPunct(tok, '(') || isWord(tok, 'DUAL', 'LATERAL')) return i;
    // JSON_TABLE(…) and friends; INSERT INTO t(a, b) is a column list.
    if (!columnsFollow && isPunct(this.t[i + 1], '(') && tok.type === 'word') return i;
    const n = this.name(i);
    if (!n) return i;
    let j = n.next;
    if (isWord(this.t[j], 'PARTITION') && isPunct(this.t[j + 1], '(')) {
      this.consumed.add(j);
      j = this.close(j + 1) + 1;
    }
    if (isWord(this.t[j], 'FOR') && isWord(this.t[j + 1], 'SYSTEM_TIME')) j += 2;
    let alias: string | null = null;
    if (isWord(this.t[j], 'AS') && isName(this.t[j + 1])) {
      alias = this.t[j + 1].value;
      this.consumed.add(j + 1);
      j += 2;
    } else if (isName(this.t[j]) && !isPunct(this.t[j + 1], '(') && !isPunct(this.t[j + 1], '.')) {
      alias = this.t[j].value;
      this.consumed.add(j);
      j++;
    }
    // USE|IGNORE|FORCE INDEX|KEY [FOR JOIN|ORDER BY|GROUP BY] (…)
    while (isWord(this.t[j], 'USE', 'IGNORE', 'FORCE') && isWord(this.t[j + 1], 'INDEX', 'KEY')) {
      j += 2;
      if (isWord(this.t[j], 'FOR')) j += isWord(this.t[j + 1], 'JOIN') ? 2 : 3;
      if (isPunct(this.t[j], '(')) j = this.close(j) + 1;
    }
    const bare = n.name.toLowerCase();
    if (!(n.name.indexOf('.') < 0 && this.ctes.has(bare))) this.refs.push({ name: this.normalize(n.name), alias: alias?.toLowerCase() ?? null, at: i });
    return j;
  }

  /** a, b, c — comma-separated table references. */
  refList(i: number): number {
    let j = this.ref(i);
    while (j > i && isPunct(this.t[j], ',')) {
      const k = this.ref(j + 1);
      if (k === j + 1) break;
      j = k;
    }
    return j;
  }

  /**
   * Walks tokens [from, to): table references after FROM / JOIN / USING / INTO / TABLE, function
   * calls, and the traits that change a query's kind (row locks, INTO OUTFILE). Returns the
   * function accesses found.
   */
  scan(from = 0, to = this.t.length, opts: { functions?: boolean } = {}): Access[] {
    const accesses: Access[] = [];
    const parens: ('func' | 'other')[] = [];
    const lists = new Set<number>();
    for (let i = from; i < to; i++) {
      const tok = this.t[i];
      const prev = this.t[i - 1];
      if (isPunct(tok, '(')) {
        const fn = i > 0 && this.isFunctionName(i - 1);
        parens.push(fn ? 'func' : 'other');
        continue;
      }
      if (isPunct(tok, ')')) {
        lists.delete(parens.length);
        parens.pop();
        continue;
      }
      const depth = parens.length;
      if (this.consumed.has(i)) continue;
      if (tok.type === 'word') {
        switch (tok.upper) {
          case 'FROM':
            // EXTRACT(YEAR FROM d), TRIM(x FROM y): not a table list.
            if (parens[depth - 1] === 'func') break;
            lists.add(depth);
            i = this.refList(i + 1) - 1;
            continue;
          case 'JOIN':
          case 'STRAIGHT_JOIN':
            lists.add(depth);
            i = this.ref(i + 1) - 1;
            continue;
          case 'USING':
            // JOIN … USING (col), CONVERT(x USING utf8mb4): not a table list.
            if (isPunct(this.t[i + 1], '(') || parens[depth - 1] === 'func') break;
            lists.add(depth);
            i = this.refList(i + 1) - 1;
            continue;
          case 'INTO':
            if (isWord(this.t[i + 1], 'OUTFILE', 'DUMPFILE')) {
              this.flags.add('select_into_file');
              accesses.push({ op: 'admin', verb: 'admin', table: null });
              break;
            }
            if (this.t[i + 1]?.type === 'var') break;
            i = this.ref(i + 1) - 1;
            continue;
          case 'TABLE':
            // TABLE t as a query (MySQL 8): at a query start, after UNION etc., or in a subquery.
            if (!prev || isPunct(prev, '(') || isWord(prev, 'UNION', 'EXCEPT', 'INTERSECT', 'ALL', 'DISTINCT')) {
              i = this.ref(i + 1) - 1;
              continue;
            }
            break;
          case 'FOR':
            if (isWord(this.t[i + 1], 'UPDATE', 'SHARE')) this.flags.add('row_locks');
            lists.delete(depth);
            break;
          case 'LOCK':
            if (isWord(this.t[i + 1], 'IN') && isWord(this.t[i + 2], 'SHARE')) this.flags.add('row_locks');
            lists.delete(depth);
            break;
          case 'NEXT':
          case 'PREVIOUS':
            // MariaDB: NEXT VALUE FOR seq advances a sequence.
            if (isWord(this.t[i + 1], 'VALUE') && isWord(this.t[i + 2], 'FOR')) {
              const n = this.name(i + 3);
              if (n && tok.upper === 'NEXT') accesses.push({ op: 'write', verb: 'function', table: this.normalize(n.name) });
              if (n) i = n.next - 1;
              continue;
            }
            break;
          case 'WHERE':
          case 'GROUP':
          case 'ORDER':
          case 'HAVING':
          case 'LIMIT':
          case 'WINDOW':
          case 'UNION':
          case 'EXCEPT':
          case 'INTERSECT':
          case 'SET':
          case 'VALUES':
          case 'SELECT':
          case 'RETURNING':
          case 'DUPLICATE':
            lists.delete(depth);
            break;
        }
      }
      if (isPunct(tok, ',') && lists.has(depth)) {
        i = this.ref(i + 1) - 1;
        continue;
      }
      if (opts.functions !== false && this.isFunctionName(i) && !this.consumed.has(i)) {
        const parts = isPunct(prev, '.') && this.t[i - 2] && this.t[i - 2].type !== 'punct' ? [this.t[i - 2].value, tok.value] : [tok.value];
        const verdict = classifyFunction(parts, this.ctx.catalog ?? null);
        if (verdict) accesses.push(verdict);
      }
    }
    return accesses;
  }

  /** Is the token at i a function name (followed by `(`, and not syntax)? */
  private isFunctionName(i: number): boolean {
    const tok = this.t[i];
    if (!tok || !isPunct(this.t[i + 1], '(')) return false;
    if (tok.type !== 'word' && tok.type !== 'ident') return false;
    if (this.consumed.has(i)) return false;
    if (tok.type === 'word' && NOT_FUNCTIONS.has(tok.upper)) return false;
    const prev = this.t[i - 1];
    if (isWord(prev, 'AS', 'INTO', 'TABLE', 'JOIN', 'FROM', 'UPDATE', 'INSERT', 'REPLACE', 'IGNORE', 'REFERENCES', 'INDEX', 'KEY')) return false;
    if (tok.type === 'word' && this.ctes.has(tok.value.toLowerCase())) return false;
    return true;
  }

  /** Index of the first depth-0 word among `words` at or after i, or -1. */
  find(i: number, ...words: string[]): number {
    let depth = 0;
    for (let j = i; j < this.t.length; j++) {
      if (isPunct(this.t[j], '(')) depth++;
      else if (isPunct(this.t[j], ')')) depth--;
      else if (depth === 0 && isWord(this.t[j], ...words)) return j;
    }
    return -1;
  }

  /** Table a name or alias refers to. */
  resolve(name: string): string {
    const lower = name.toLowerCase();
    return this.refs.find((r) => r.alias === lower)?.name ?? this.normalize(name);
  }
}

function result(command: string, accesses: Access[], flags: Iterable<string>, base?: { op: Operation; verb: Verb }): Partial {
  const all = [...accesses];
  if (base && !all.some((a) => a.op === base.op)) all.unshift({ op: base.op, verb: base.verb, table: null });
  const deduped = dedupe(all);
  return { command, kind: kindOf(deduped), accesses: deduped, flags: [...new Set(flags)] };
}

// ─── queries and DML ─────────────────────────────────────────────────────────

/** SELECT / TABLE / VALUES / (SELECT …) UNION …, and WITH … SELECT. */
function classifySelect(s: Stmt, command = 'SELECT'): Partial {
  const funcs = s.scan();
  if (s.flags.has('select_into_file')) return admin(`${command} INTO OUTFILE`, 'select_into_file');
  const locks = s.flags.has('row_locks');
  const tables: Access[] = s.refs.map((r) => (locks ? { op: 'write', verb: 'lock', table: r.name } : { op: 'read', verb: 'select', table: r.name }));
  // SELECT @@version, SELECT 1, SELECT NOW(): no data touched, nothing to decide.
  if (tables.length === 0 && funcs.length === 0 && !locks) return session(command, ['no_tables']);
  return result(command, [...tables, ...funcs], s.flags, locks ? { op: 'write', verb: 'lock' } : { op: 'read', verb: 'select' });
}

/** INSERT / REPLACE [LOW_PRIORITY|DELAYED|HIGH_PRIORITY] [IGNORE] [INTO] t … [ON DUPLICATE KEY UPDATE …] */
function classifyInsert(s: Stmt, start: number): Partial {
  const verb = s.word(start)!;
  let i = start + 1;
  while (isWord(s.t[i], 'LOW_PRIORITY', 'DELAYED', 'HIGH_PRIORITY', 'IGNORE')) s.consumed.add(i++);
  if (isWord(s.t[i], 'INTO')) s.consumed.add(i++);
  s.ref(i, true);
  const target = s.refs.find((r) => r.at === i)?.name ?? null;
  const funcs = s.scan(i);
  const accesses: Access[] = [{ op: 'write', verb: 'insert', table: target }];
  if (verb === 'REPLACE') accesses.push({ op: 'write', verb: 'delete', table: target });
  const dup = s.find(i, 'DUPLICATE');
  if (dup > 0 && isWord(s.t[dup - 1], 'ON')) accesses.push({ op: 'write', verb: 'update', table: target });
  for (const r of s.refs) if (r.at !== i) accesses.push(lockedOrRead(s, r.name));
  return result(verb, [...accesses, ...funcs], s.flags);
}

const lockedOrRead = (s: Stmt, table: string): Access =>
  s.flags.has('row_locks') ? { op: 'write', verb: 'lock', table } : { op: 'read', verb: 'select', table };

/**
 * UPDATE [LOW_PRIORITY] [IGNORE] t [, u | JOIN u …] SET … — every table in the UPDATE clause may be
 * written, except those inside a derived table (a subquery there is read-only).
 */
function classifyUpdate(s: Stmt, start: number): Partial {
  let i = start + 1;
  while (isWord(s.t[i], 'LOW_PRIORITY', 'IGNORE')) s.consumed.add(i++);
  const set = s.find(i, 'SET');
  const end = set < 0 ? s.t.length : set;
  const before = s.refs.length;
  s.refList(i);
  const headFuncs = s.scan(i, end);
  const topLevel = new Set<number>();
  for (let j = i, depth = 0; j < end; j++) {
    if (isPunct(s.t[j], '(')) depth++;
    else if (isPunct(s.t[j], ')')) depth--;
    else if (depth === 0) topLevel.add(j);
  }
  const head = s.refs.slice(before).filter((r) => topLevel.has(r.at));
  const funcs = [...headFuncs, ...s.scan(end)];
  const headSet = new Set(head);
  const accesses: Access[] = head.map((r) => ({ op: 'write', verb: 'update', table: r.name }));
  for (const r of s.refs) if (!headSet.has(r)) accesses.push(lockedOrRead(s, r.name));
  if (s.find(end, 'WHERE') < 0) s.flags.add('no_where');
  return result('UPDATE', [...accesses, ...funcs], s.flags, { op: 'write', verb: 'update' });
}

/**
 * DELETE [LOW_PRIORITY] [QUICK] [IGNORE] FROM t …                      (single table)
 * DELETE … t1[.*], t2 FROM refs …  /  DELETE … FROM t1, t2 USING refs …  (multi-table: only the listed tables lose rows)
 */
function classifyDelete(s: Stmt, start: number): Partial {
  let i = start + 1;
  while (isWord(s.t[i], 'LOW_PRIORITY', 'QUICK', 'IGNORE')) s.consumed.add(i++);
  const targets: string[] = [];
  const readTargets = (j: number): number => {
    for (;;) {
      if (!isName(s.t[j])) return j;
      let name = s.t[j].value;
      s.consumed.add(j);
      j++;
      if (isPunct(s.t[j], '.') && (s.t[j + 1]?.type === 'word' || s.t[j + 1]?.type === 'ident')) {
        name = `${name}.${s.t[j + 1].value}`;
        s.consumed.add(j + 1);
        j += 2;
      }
      if (isPunct(s.t[j], '.') && isPunct(s.t[j + 1], '*')) j += 2;
      targets.push(name);
      if (!isPunct(s.t[j], ',')) return j;
      j++;
    }
  };
  let multi = false;
  if (isWord(s.t[i], 'FROM')) {
    const using = s.find(i, 'USING');
    if (using > 0) {
      multi = true;
      s.consumed.add(i);
      readTargets(i + 1);
    }
  } else if (isName(s.t[i])) {
    multi = true;
    readTargets(i);
  }
  const funcs = s.scan(start + 1);
  const accesses: Access[] = [];
  if (multi) {
    const resolved = new Set(targets.map((t) => s.resolve(t)));
    for (const t of resolved) accesses.push({ op: 'write', verb: 'delete', table: t });
    for (const r of s.refs) if (!resolved.has(r.name)) accesses.push(lockedOrRead(s, r.name));
  } else {
    const [first, ...rest] = s.refs;
    accesses.push({ op: 'write', verb: 'delete', table: first?.name ?? null });
    for (const r of rest) accesses.push(lockedOrRead(s, r.name));
  }
  if (s.find(start + 1, 'WHERE') < 0) s.flags.add('no_where');
  return result('DELETE', [...accesses, ...funcs], s.flags, { op: 'write', verb: 'delete' });
}

/** Main keyword of a WITH statement (after its CTE list). */
function afterWith(s: Stmt): number {
  let j = 1;
  if (isWord(s.t[j], 'RECURSIVE')) j++;
  for (;;) {
    j++;
    if (isPunct(s.t[j], '(')) j = s.close(j) + 1;
    if (!isWord(s.t[j], 'AS')) return j;
    j = s.close(j + 1) + 1;
    if (!isPunct(s.t[j], ',')) return j;
    j++;
  }
}

// ─── DDL ─────────────────────────────────────────────────────────────────────

const ADMIN_OBJECTS = new Set([
  'DATABASE',
  'SCHEMA',
  'USER',
  'ROLE',
  'SERVER',
  'TABLESPACE',
  'LOGFILE',
  'RESOURCE',
  'SPATIAL',
  'UNDO',
  'EVENT',
  'INSTANCE',
  'PACKAGE',
]);

/** Skip CREATE/ALTER modifiers; returns the object keyword's index and whether a DEFINER was named. */
function objectKeyword(s: Stmt, i: number): { at: number; definer: boolean } {
  let definer = false;
  for (;;) {
    const w = s.word(i);
    if (w === 'OR' && s.word(i + 1) === 'REPLACE') i += 2;
    else if (w === 'TEMPORARY' || w === 'UNIQUE' || w === 'FULLTEXT' || w === 'ONLINE' || w === 'OFFLINE' || w === 'AGGREGATE' || w === 'IGNORE') i++;
    else if (w === 'SPATIAL' && s.word(i + 1) === 'INDEX') i++;
    else if (w === 'ALGORITHM' && isPunct(s.t[i + 1], '=')) i += 3;
    else if (w === 'SQL' && s.word(i + 1) === 'SECURITY') i += 3;
    else if (w === 'DEFINER' && isPunct(s.t[i + 1], '=')) {
      definer = true;
      i += 2;
      // 'user'@'host' | user@host | CURRENT_USER[()]
      while (i < s.t.length && !isWord(s.t[i], 'PROCEDURE', 'FUNCTION', 'TRIGGER', 'EVENT', 'VIEW', 'SQL', 'ALGORITHM')) i++;
    } else return { at: i, definer };
  }
}

function ifExists(s: Stmt, i: number): number {
  if (isWord(s.t[i], 'IF') && isWord(s.t[i + 1], 'NOT') && isWord(s.t[i + 2], 'EXISTS')) return i + 3;
  if (isWord(s.t[i], 'IF') && isWord(s.t[i + 1], 'EXISTS')) return i + 2;
  return i;
}

/** Comma-separated object names starting at i. */
function nameList(s: Stmt, i: number): string[] {
  const out: string[] = [];
  for (;;) {
    const n = s.name(i);
    if (!n) return out;
    out.push(s.normalize(n.name));
    if (!isPunct(s.t[n.next], ',')) return out;
    i = n.next + 1;
  }
}

/** Tables and functions read by the query part of CREATE TABLE … AS SELECT / CREATE VIEW … AS SELECT. */
function queryPart(s: Stmt, from: number): Access[] {
  const q = s.find(from, 'SELECT', 'WITH', 'TABLE', 'VALUES');
  const inner = s.t.findIndex((t, j) => j >= from && isWord(t, 'SELECT'));
  const at = q >= 0 ? q : inner;
  if (at < 0) return [];
  const before = s.refs.length;
  const funcs = s.scan(at);
  return [...s.refs.slice(before).map((r) => lockedOrRead(s, r.name)), ...funcs];
}

function classifyCreate(s: Stmt, absorbed: boolean): Partial {
  const { at, definer } = objectKeyword(s, 1);
  const object = s.word(at) ?? '';
  const command = `CREATE ${object}`.trim();
  if (definer) return admin(command, 'definer');
  if (absorbed) return admin(command, 'compound_statement');
  const ddl = (table: string | null, extra: Access[] = []) => result(command, [{ op: 'ddl', verb: 'create', table }, ...extra], s.flags);
  switch (object) {
    case 'TABLE': {
      const n = s.name(ifExists(s, at + 1));
      if (!n) return admin(command, 'unparseable');
      const extra: Access[] = [];
      // CREATE TABLE t LIKE src / CREATE TABLE t (LIKE src)
      const like = isWord(s.t[n.next], 'LIKE') ? n.next + 1 : isPunct(s.t[n.next], '(') && isWord(s.t[n.next + 1], 'LIKE') ? n.next + 2 : -1;
      if (like > 0) {
        const src = s.name(like);
        if (src) extra.push({ op: 'read', verb: 'select', table: s.normalize(src.name) });
      }
      return ddl(s.normalize(n.name), [...extra, ...queryPart(s, n.next)]);
    }
    case 'INDEX': {
      const on = s.find(at, 'ON');
      const n = on > 0 ? s.name(on + 1) : null;
      return ddl(n ? s.normalize(n.name) : null);
    }
    case 'VIEW': {
      const n = s.name(at + 1);
      return ddl(n ? s.normalize(n.name) : null, queryPart(s, at + 1));
    }
    case 'TRIGGER': {
      const on = s.find(at, 'ON');
      const n = on > 0 ? s.name(on + 1) : null;
      return ddl(n ? s.normalize(n.name) : null);
    }
    case 'PROCEDURE':
    case 'FUNCTION':
      if (s.find(at, 'SONAME') >= 0) return admin(command, 'loadable_function');
      return ddl(null);
    case 'SEQUENCE': {
      const n = s.name(ifExists(s, at + 1));
      return ddl(n ? s.normalize(n.name) : null);
    }
    default:
      return admin(command, ADMIN_OBJECTS.has(object) ? 'privileged_object' : 'unrecognized');
  }
}

function classifyAlter(s: Stmt): Partial {
  const { at, definer } = objectKeyword(s, 1);
  const object = s.word(at) ?? '';
  const command = `ALTER ${object}`.trim();
  if (definer) return admin(command, 'definer');
  const ddl = (tables: (string | null)[], extra: Access[] = []) =>
    result(command, [...tables.map((table): Access => ({ op: 'ddl', verb: 'alter', table })), ...extra], s.flags);
  switch (object) {
    case 'TABLE': {
      const n = s.name(ifExists(s, at + 1));
      if (!n) return admin(command, 'unparseable');
      const tables = [s.normalize(n.name)];
      const rename = s.find(n.next, 'RENAME');
      if (rename > 0) {
        let j = rename + 1;
        if (isWord(s.t[j], 'TO', 'AS')) j++;
        const to = s.name(j);
        if (to && !isWord(s.t[rename + 1], 'COLUMN', 'INDEX', 'KEY')) tables.push(s.normalize(to.name));
      }
      return ddl(tables);
    }
    case 'VIEW': {
      const n = s.name(at + 1);
      return ddl([n ? s.normalize(n.name) : null], queryPart(s, at + 1));
    }
    case 'PROCEDURE':
    case 'FUNCTION':
      return ddl([null]);
    case 'SEQUENCE': {
      const n = s.name(ifExists(s, at + 1));
      return ddl([n ? s.normalize(n.name) : null]);
    }
    default:
      return admin(command, ADMIN_OBJECTS.has(object) ? 'privileged_object' : 'unrecognized');
  }
}

function classifyDrop(s: Stmt): Partial {
  let at = 1;
  if (isWord(s.t[at], 'TEMPORARY')) at++;
  const object = s.word(at) ?? '';
  const command = `DROP ${object === 'TABLES' ? 'TABLE' : object}`.trim();
  const drop = (tables: (string | null)[]) =>
    result(command, tables.length ? tables.map((table): Access => ({ op: 'ddl', verb: 'drop', table })) : [{ op: 'ddl', verb: 'drop', table: null }], [
      ...s.flags,
      'destructive',
    ]);
  switch (object) {
    case 'TABLE':
    case 'TABLES':
    case 'VIEW':
    case 'SEQUENCE':
      return drop(nameList(s, ifExists(s, at + 1)));
    case 'INDEX': {
      const on = s.find(at, 'ON');
      const n = on > 0 ? s.name(on + 1) : null;
      return drop([n ? s.normalize(n.name) : null]);
    }
    case 'PROCEDURE':
    case 'FUNCTION':
    case 'TRIGGER':
      return drop([null]);
    case 'PREPARE':
      return session('DEALLOCATE PREPARE', ['prepared_statement']);
    default:
      return admin(command, ADMIN_OBJECTS.has(object) ? 'privileged_object' : 'unrecognized');
  }
}

// ─── SET ─────────────────────────────────────────────────────────────────────

/** Top-level comma-separated pieces of tokens [from, to). */
function splitCommas(s: Stmt, from: number, to: number): [number, number][] {
  const out: [number, number][] = [];
  let depth = 0;
  let start = from;
  for (let j = from; j < to; j++) {
    if (isPunct(s.t[j], '(')) depth++;
    else if (isPunct(s.t[j], ')')) depth--;
    else if (depth === 0 && isPunct(s.t[j], ',')) {
      out.push([start, j]);
      start = j + 1;
    }
  }
  if (start < to) out.push([start, to]);
  return out;
}

const charsetOk = (t: Token | undefined) => !!t && (t.type === 'word' || t.type === 'string' || t.type === 'ident') && SAFE_CHARSETS.test(t.value.toLowerCase());

/**
 * One assignment (`[scope] var = expr`): null if it is a harmless session setting, otherwise why
 * it isn't. Expression side effects (subqueries, functions) are added to `accesses`.
 */
function checkAssignment(s: Stmt, from: number, to: number, accesses: Access[]): string | null {
  let i = from;
  let scope = 'SESSION';
  const w = s.word(i);
  if (w === 'GLOBAL' || w === 'PERSIST' || w === 'PERSIST_ONLY' || w === 'SESSION' || w === 'LOCAL') {
    scope = w === 'LOCAL' ? 'SESSION' : w;
    i++;
  }
  const tok = s.t[i];
  if (!tok) return 'unparseable';
  let name: string;
  if (tok.type === 'var') {
    // @user_var = expr: only the expression matters.
    const before = s.refs.length;
    const funcs = s.scan(i + 1, to);
    accesses.push(...s.refs.slice(before).map((r) => lockedOrRead(s, r.name)), ...funcs);
    return null;
  }
  if (tok.type === 'sysvar') {
    const parts = tok.value.toLowerCase().split('.');
    if (parts.length > 1) {
      if (parts[0] === 'global' || parts[0] === 'persist' || parts[0] === 'persist_only') scope = 'GLOBAL';
      name = parts.slice(1).join('.');
    } else name = parts[0];
  } else if (tok.type === 'word' || tok.type === 'ident') {
    name = tok.value.toLowerCase();
  } else return 'unparseable';
  if (scope !== 'SESSION') return 'global_setting';
  if (!SESSION_VARIABLES.has(name)) return 'privileged_setting';
  let eq = i + 1;
  if (!isPunct(s.t[eq], '=') && !isPunct(s.t[eq], ':=')) return 'unparseable';
  eq++;
  if (CHARSET_VARIABLES.has(name) && !(eq === to - 1 && charsetOk(s.t[eq]))) return 'unsafe_charset';
  const before = s.refs.length;
  const funcs = s.scan(eq, to);
  accesses.push(...s.refs.slice(before).map((r) => lockedOrRead(s, r.name)), ...funcs);
  return null;
}

function classifySet(s: Stmt): Partial {
  const w1 = s.word(1);
  const w2 = s.word(2);
  if (w1 === 'NAMES' || w1 === 'CHARSET' || (w1 === 'CHARACTER' && w2 === 'SET')) {
    const value = s.t[w1 === 'CHARACTER' ? 3 : 2];
    if (!charsetOk(value)) return admin(`SET ${w1 === 'NAMES' ? 'NAMES' : 'CHARACTER SET'}`, 'unsafe_charset');
    const collate = s.t.findIndex((t) => isWord(t, 'COLLATE'));
    if (collate > 0 && !charsetOk(s.t[collate + 1])) return admin('SET NAMES', 'unsafe_charset');
    return session(w1 === 'NAMES' ? 'SET NAMES' : 'SET CHARACTER SET', ['session_setting']);
  }
  if (w1 === 'TRANSACTION' || ((w1 === 'SESSION' || w1 === 'LOCAL') && w2 === 'TRANSACTION')) return session('SET TRANSACTION', ['session_setting']);
  if ((w1 === 'GLOBAL' || w1 === 'PERSIST') && w2 === 'TRANSACTION') return admin('SET GLOBAL TRANSACTION', 'global_setting');
  if (w1 === 'PASSWORD' || w1 === 'ROLE' || w1 === 'DEFAULT' || w1 === 'RESOURCE') return admin(`SET ${w1}`, 'privileged_setting');
  if (w1 === 'STATEMENT') {
    // MariaDB: SET STATEMENT var=value[, …] FOR <statement>
    const forAt = s.find(2, 'FOR');
    if (forAt < 0) return admin('SET STATEMENT', 'unparseable');
    const accesses: Access[] = [];
    for (const [a, b] of splitCommas(s, 2, forAt)) {
      const why = checkAssignment(s, a, b, accesses);
      if (why) return admin('SET STATEMENT', why);
    }
    const inner = classifyTokens(s.t.slice(forAt + 1), s.ctx, false);
    return { ...inner, command: `SET STATEMENT … FOR ${inner.command}`, accesses: dedupe([...inner.accesses, ...accesses]), kind: kindOf(dedupe([...inner.accesses, ...accesses])) };
  }
  const accesses: Access[] = [];
  for (const [a, b] of splitCommas(s, 1, s.t.length)) {
    const why = checkAssignment(s, a, b, accesses);
    if (why) return admin(`SET ${s.t[a]?.value ?? ''}`.trim(), why);
  }
  return { ...result('SET', accesses, ['session_setting']), flags: ['session_setting'] };
}

// ─── everything else ─────────────────────────────────────────────────────────


const ADMIN_COMMANDS = new Set([
  'GRANT',
  'REVOKE',
  'FLUSH',
  'RESET',
  'PURGE',
  'INSTALL',
  'UNINSTALL',
  'SHUTDOWN',
  'RESTART',
  'CLONE',
  'CHANGE',
  'STOP',
  'OPTIMIZE',
  'REPAIR',
  'CHECK',
  'CHECKSUM',
  'CACHE',
  'BINLOG',
  'IMPORT',
  'BACKUP',
  'XA',
  'LOAD',
]);

/** SHOW variants that only describe the session or server, not data. */
const SESSION_SHOWS = new Set(['VARIABLES', 'STATUS', 'WARNINGS', 'ERRORS', 'COLLATION', 'CHARACTER', 'CHARSET', 'ENGINES', 'COUNT', 'PROFILES', 'PROFILE']);

function classifyShow(s: Stmt): Partial {
  let i = 1;
  while (isWord(s.t[i], 'GLOBAL', 'SESSION', 'FULL', 'EXTENDED')) i++;
  const what = s.word(i) ?? '';
  if (SESSION_SHOWS.has(what)) return session(`SHOW ${what}`);
  let table: string | null = null;
  if (what === 'CREATE' && isWord(s.t[i + 1], 'TABLE', 'VIEW', 'SEQUENCE')) {
    const n = s.name(i + 2);
    if (n) table = s.normalize(n.name);
  } else if (['COLUMNS', 'FIELDS', 'INDEX', 'INDEXES', 'KEYS'].includes(what) && isWord(s.t[i + 1], 'FROM', 'IN')) {
    const n = s.name(i + 2);
    if (n) {
      // SHOW COLUMNS FROM t FROM db
      const db = isWord(s.t[n.next], 'FROM', 'IN') ? s.t[n.next + 1]?.value : null;
      table = s.normalize(db ? `${db}.${n.name}` : n.name);
    }
  }
  return { command: `SHOW ${what}`.trim(), kind: 'read', accesses: [{ op: 'read', verb: 'select', table }], flags: [] };
}

/** Plain EXPLAIN plans without running: DML becomes a read of the same tables. Functions keep their verdict. */
function asPlan(inner: Partial): Partial {
  const accesses = dedupe(
    inner.accesses.map((a): Access => (a.op === 'write' && a.verb !== 'function' && a.verb !== 'call' ? { op: 'read', verb: 'select', table: a.table } : a)),
  );
  return { command: `EXPLAIN ${inner.command}`, kind: accesses.length ? kindOf(accesses) : 'read', accesses: accesses.length ? accesses : [{ op: 'read', verb: 'select', table: null }], flags: [] };
}

const EXPLAINABLE = new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'TABLE', 'WITH', 'VALUES']);

function classifyExplain(s: Stmt): Partial {
  let i = 1;
  const analyze = isWord(s.t[i], 'ANALYZE');
  if (analyze) i++;
  for (;;) {
    if (isWord(s.t[i], 'FORMAT') && isPunct(s.t[i + 1], '=')) i += 3;
    else if (isWord(s.t[i], 'EXTENDED', 'PARTITIONS')) i++;
    else break;
  }
  if (isWord(s.t[i], 'FOR') && isWord(s.t[i + 1], 'CONNECTION')) return { command: 'EXPLAIN FOR CONNECTION', kind: 'read', accesses: [{ op: 'read', verb: 'select', table: null }], flags: [] };
  if (!analyze && !EXPLAINABLE.has(s.word(i) ?? '') && !isPunct(s.t[i], '(')) {
    // DESCRIBE t [column]
    const n = s.name(i);
    if (!n) return admin('EXPLAIN', 'unparseable');
    return { command: 'DESCRIBE', kind: 'read', accesses: [{ op: 'read', verb: 'select', table: s.normalize(n.name) }], flags: [] };
  }
  const inner = classifyTokens(s.t.slice(i), s.ctx, false);
  if (analyze) return { ...inner, command: `EXPLAIN ANALYZE ${inner.command}`, flags: [...inner.flags, 'explain_analyze'] };
  return asPlan(inner);
}

function classifyPrepared(s: Stmt, verb: string): Partial {
  const name = s.t[1]?.value.toLowerCase();
  if (!name) return admin(verb, 'unparseable');
  if (verb === 'PREPARE') {
    if (!isWord(s.t[2], 'FROM')) return admin('PREPARE', 'unparseable');
    const src = s.t[3];
    // PREPARE … FROM @var: we can't see what it will contain.
    if (src?.type !== 'string' || s.t.length > 4) return admin('PREPARE', 'dynamic_sql');
    const inner = analyzeMysql(src.value, { ...s.ctx, prepared: undefined });
    if (inner.statements.length !== 1) return admin('PREPARE', inner.error ? 'unparseable' : 'multiple_statements');
    return { command: 'PREPARE', kind: 'session', accesses: [], flags: ['prepared_statement'], prepared: { name, analysis: inner.statements[0] } };
  }
  const prepared = s.ctx.prepared?.get(name);
  if (!prepared) return admin('EXECUTE', 'unknown_prepared_statement');
  return { command: `EXECUTE (${prepared.command})`, kind: prepared.kind, accesses: prepared.accesses, flags: [...prepared.flags, 'prepared_statement'] };
}

function classifyTokens(tokens: Token[], ctx: MysqlAnalyzeContext, absorbed: boolean): Partial {
  const s = new Stmt(tokens, ctx);
  if (tokens.length === 0) return session('EMPTY');
  if (isPunct(tokens[0], '(')) return classifySelect(s);
  const w = s.word(0);
  switch (w) {
    case 'SELECT':
    case 'TABLE':
    case 'VALUES':
      return classifySelect(s, w);
    case 'WITH': {
      const main = afterWith(s);
      const mw = s.word(main);
      if (mw === 'UPDATE') return classifyUpdate(s, main);
      if (mw === 'DELETE') return classifyDelete(s, main);
      if (mw === 'SELECT' || mw === 'TABLE' || mw === 'VALUES' || isPunct(tokens[main], '(')) return classifySelect(s);
      return admin('WITH', 'unparseable');
    }
    case 'INSERT':
    case 'REPLACE':
      return classifyInsert(s, 0);
    case 'UPDATE':
      return classifyUpdate(s, 0);
    case 'DELETE':
      return classifyDelete(s, 0);
    case 'CALL': {
      const paren = tokens.findIndex((t) => isPunct(t, '('));
      const funcs = paren > 0 ? s.scan(paren) : [];
      return result('CALL', [{ op: 'write', verb: 'call', table: null }, ...funcs], s.flags);
    }
    case 'DO': {
      const funcs = s.scan(1);
      const tables = s.refs.map((r) => lockedOrRead(s, r.name));
      return tables.length || funcs.length ? result('DO', [...tables, ...funcs], s.flags) : session('DO');
    }
    case 'HANDLER': {
      const n = s.name(1);
      return { command: 'HANDLER', kind: 'read', accesses: [{ op: 'read', verb: 'select', table: n ? s.normalize(n.name) : null }], flags: [] };
    }
    case 'EXPLAIN':
    case 'DESCRIBE':
    case 'DESC':
      return classifyExplain(s);
    case 'ANALYZE': {
      // MariaDB: ANALYZE [FORMAT=JSON] <statement> runs it. ANALYZE TABLE is maintenance.
      let i = 1;
      if (isWord(tokens[i], 'FORMAT') && isPunct(tokens[i + 1], '=')) i += 3;
      if (EXPLAINABLE.has(s.word(i) ?? '') && s.word(i) !== 'TABLE') {
        const inner = classifyTokens(tokens.slice(i), ctx, false);
        return { ...inner, command: `ANALYZE ${inner.command}`, flags: [...inner.flags, 'explain_analyze'] };
      }
      return admin('ANALYZE TABLE', 'maintenance');
    }
    case 'SHOW':
      return classifyShow(s);
    case 'HELP':
    case 'GET':
    case 'SIGNAL':
    case 'RESIGNAL':
      return session(w);
    case 'SET':
      return classifySet(s);
    case 'START':
      if (isWord(tokens[1], 'TRANSACTION')) return session('BEGIN', ['transaction_control']);
      return admin(`START ${s.word(1) ?? ''}`.trim(), 'replication');
    case 'BEGIN':
      if (isWord(tokens[1], 'NOT') && isWord(tokens[2], 'ATOMIC')) return admin('BEGIN NOT ATOMIC', 'compound_statement');
      return session('BEGIN', ['transaction_control']);
    case 'COMMIT':
    case 'ROLLBACK':
    case 'SAVEPOINT':
    case 'RELEASE':
      return session(w === 'ROLLBACK' && isWord(tokens[1], 'TO') ? 'ROLLBACK TO SAVEPOINT' : w, ['transaction_control']);
    case 'LOCK':
      if (isWord(tokens[1], 'TABLES', 'TABLE')) {
        // LOCK TABLES t [AS a] READ [LOCAL], u WRITE
        for (const [a] of splitCommas(s, 2, tokens.length)) s.ref(a);
        return result('LOCK TABLES', s.refs.map((r): Access => ({ op: 'write', verb: 'lock', table: r.name })), ['table_locks'], { op: 'write', verb: 'lock' });
      }
      return admin(`LOCK ${s.word(1) ?? ''}`.trim(), 'privileged');
    case 'UNLOCK':
      if (isWord(tokens[1], 'TABLES', 'TABLE')) return session('UNLOCK TABLES', ['table_locks']);
      return admin(`UNLOCK ${s.word(1) ?? ''}`.trim(), 'privileged');
    case 'USE': {
      const db = tokens[1]?.value.toLowerCase();
      const current = [ctx.database, ...(ctx.databaseAliases ?? [])].filter(Boolean).map((d) => d!.toLowerCase());
      if (db && current.includes(db)) return session('USE', ['use_database']);
      return admin('USE', 'other_database');
    }
    case 'PREPARE':
    case 'EXECUTE':
      return classifyPrepared(s, w);
    case 'DEALLOCATE':
      return session('DEALLOCATE PREPARE', ['prepared_statement']);
    case 'KILL': {
      const kind = isWord(tokens[1], 'QUERY') ? 'QUERY' : 'CONNECTION';
      return admin(`KILL ${kind}`, kind === 'QUERY' ? 'kill_query' : 'kill_connection');
    }
    case 'CREATE':
      return classifyCreate(s, absorbed);
    case 'ALTER':
      return classifyAlter(s);
    case 'DROP':
      return classifyDrop(s);
    case 'RENAME': {
      if (!isWord(tokens[1], 'TABLE', 'TABLES')) return admin(`RENAME ${s.word(1) ?? ''}`.trim(), 'privileged_object');
      // RENAME TABLE a TO b [, c TO d]
      const tables: Access[] = [];
      for (const [a] of splitCommas(s, 2, tokens.length)) {
        const from = s.name(a);
        const to = from && isWord(tokens[from.next], 'TO') ? s.name(from.next + 1) : null;
        for (const n of [from, to]) if (n) tables.push({ op: 'ddl', verb: 'alter', table: s.normalize(n.name) });
      }
      return result('RENAME TABLE', tables, [], { op: 'ddl', verb: 'alter' });
    }
    case 'TRUNCATE': {
      const n = s.name(isWord(tokens[1], 'TABLE') ? 2 : 1);
      return result('TRUNCATE', [{ op: 'write', verb: 'truncate', table: n ? s.normalize(n.name) : null }], ['destructive']);
    }
    default:
      if (w && ADMIN_COMMANDS.has(w)) return admin(w === 'LOAD' ? `LOAD ${s.word(1) ?? ''}`.trim() : w, w === 'LOAD' ? 'server_files' : 'privileged');
      return admin(w ?? 'UNKNOWN', absorbed ? 'compound_statement' : 'unrecognized');
  }
}

/** Is a statement starting at i a stored-program definition or a compound block (its body may contain `;`)? */
function isCompound(tokens: Token[], i: number): boolean {
  const w = (k: number) => (tokens[k]?.type === 'word' ? tokens[k].upper : null);
  const first = w(i);
  if (first === 'BEGIN' && w(i + 1) === 'NOT' && w(i + 2) === 'ATOMIC') return true;
  // MariaDB runs IF/CASE/LOOP/WHILE/REPEAT/FOR blocks outside stored programs; `label: BEGIN …` too.
  if (first && ['IF', 'CASE', 'LOOP', 'WHILE', 'REPEAT', 'FOR'].includes(first)) return true;
  if (tokens[i + 1]?.type === 'punct' && tokens[i + 1].value === ':') return true;
  if (first !== 'CREATE') return false;
  for (let k = i + 1; k < Math.min(tokens.length, i + 16); k++) {
    const kw = w(k);
    if (kw === 'PROCEDURE' || kw === 'FUNCTION' || kw === 'TRIGGER' || kw === 'EVENT') return true;
    if (kw && ['TABLE', 'VIEW', 'INDEX', 'DATABASE', 'SCHEMA', 'USER', 'ROLE', 'SEQUENCE', 'SERVER'].includes(kw)) return false;
  }
  return false;
}

/**
 * Splits at top-level `;`. A stored-program definition with a multi-statement body can't be split
 * without a full grammar, so it takes the rest of the input as one statement and is marked
 * compound (which makes it admin): whatever follows is then shown to, and decided by, a human.
 */
function split(tokens: Token[]): { tokens: Token[]; absorbed: boolean }[] {
  const out: { tokens: Token[]; absorbed: boolean }[] = [];
  let i = 0;
  while (i < tokens.length) {
    if (tokens[i].type === 'punct' && tokens[i].value === ';') {
      i++;
      continue;
    }
    let end = tokens.findIndex((t, k) => k >= i && t.type === 'punct' && t.value === ';');
    if (end < 0) end = tokens.length;
    if (isCompound(tokens, i)) {
      const rest = tokens.slice(end).some((t) => !(t.type === 'punct' && t.value === ';'));
      if (rest) {
        let last = tokens.length;
        while (last > i && tokens[last - 1].type === 'punct' && tokens[last - 1].value === ';') last--;
        out.push({ tokens: tokens.slice(i, last), absorbed: true });
        break;
      }
    }
    out.push({ tokens: tokens.slice(i, end), absorbed: false });
    i = end + 1;
  }
  return out;
}

export function analyzeMysql(sql: string, ctx: MysqlAnalyzeContext = {}): Analysis {
  let tokens: Token[];
  try {
    tokens = lex(sql, ctx);
  } catch (err) {
    const message = err instanceof LexError ? err.message : String(err);
    return {
      statements: [{ text: sql.trim(), command: 'UNPARSEABLE', kind: 'admin', accesses: [{ op: 'admin', verb: 'admin', table: null }], flags: ['unparseable'] }],
      error: message,
    };
  }
  // A PREPARE earlier in the same string is known to a later EXECUTE.
  const prepared = new Map(ctx.prepared);
  const statements = split(tokens).map(({ tokens: t, absorbed }): StatementAnalysis => {
    const text = sliceTokens(sql, t);
    let partial: Partial;
    try {
      partial = classifyTokens(t, { ...ctx, prepared }, absorbed);
    } catch {
      partial = admin('UNKNOWN', 'classification_failed');
    }
    if (absorbed && partial.kind !== 'admin') partial = admin(partial.command, 'compound_statement');
    if (partial.prepared) prepared.set(partial.prepared.name, partial.prepared.analysis);
    return { text, ...partial };
  });
  return { statements, error: null };
}
