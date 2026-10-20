import { loadModule, parseSync } from 'libpg-query';
import { OPERATION_RANK, type Access, type Analysis, type Operation, type StatementAnalysis, type Verb } from '../types.js';
import { classifyFunction, type FunctionCatalog } from './functions.js';

/**
 * Classifies SQL with Postgres's own parser (libpg-query, compiled to WASM). Principles:
 *  - Anything we don't recognise — unmapped statement types, parse errors — is `admin`
 *    (denied by default). Unknown must never mean "read".
 *  - A statement's kind is the strictest of everything it does, including nested DML in CTEs,
 *    row locks, side-effecting functions, and what EXPLAIN ANALYZE would execute.
 */

let ready: Promise<void> | null = null;
/** The WASM module must be loaded once before analyze() is used. */
export function initAnalyzer(): Promise<void> {
  return (ready ??= loadModule());
}

export interface AnalyzeContext {
  /** Function volatility snapshot from the target database (see executor). */
  catalog?: FunctionCatalog | null;
  /** Statements prepared earlier in this session (PREPARE name AS …), for EXECUTE. */
  prepared?: Map<string, StatementAnalysis>;
}

type Node = Record<string, any>;

/** Settings a client may change freely. Everything else (role, session_authorization, read-only flags, …) is admin. */
const SESSION_SETTINGS = new Set([
  'application_name',
  'client_encoding',
  'datestyle',
  'timezone',
  'time zone',
  'intervalstyle',
  'extra_float_digits',
  'statement_timeout',
  'lock_timeout',
  'search_path',
  'client_min_messages',
  'bytea_output',
  'transaction_isolation',
  'default_transaction_isolation',
  'work_mem',
  'jit',
  'enable_seqscan',
  'enable_indexscan',
  'enable_bitmapscan',
]);

const STATEMENT_KINDS: Record<string, { kind: Operation; command: string }> = {
  // write
  TruncateStmt: { kind: 'write', command: 'TRUNCATE' },
  LockStmt: { kind: 'write', command: 'LOCK' },
  NotifyStmt: { kind: 'write', command: 'NOTIFY' },
  CallStmt: { kind: 'write', command: 'CALL' },
  RefreshMatViewStmt: { kind: 'write', command: 'REFRESH MATERIALIZED VIEW' },
  // ddl
  CreateStmt: { kind: 'ddl', command: 'CREATE TABLE' },
  AlterTableStmt: { kind: 'ddl', command: 'ALTER TABLE' },
  DropStmt: { kind: 'ddl', command: 'DROP' },
  IndexStmt: { kind: 'ddl', command: 'CREATE INDEX' },
  ViewStmt: { kind: 'ddl', command: 'CREATE VIEW' },
  CreateTableAsStmt: { kind: 'ddl', command: 'CREATE TABLE AS' },
  RenameStmt: { kind: 'ddl', command: 'ALTER … RENAME' },
  CommentStmt: { kind: 'ddl', command: 'COMMENT' },
  CreateSeqStmt: { kind: 'ddl', command: 'CREATE SEQUENCE' },
  AlterSeqStmt: { kind: 'ddl', command: 'ALTER SEQUENCE' },
  CompositeTypeStmt: { kind: 'ddl', command: 'CREATE TYPE' },
  CreateEnumStmt: { kind: 'ddl', command: 'CREATE TYPE' },
  AlterEnumStmt: { kind: 'ddl', command: 'ALTER TYPE' },
  CreateRangeStmt: { kind: 'ddl', command: 'CREATE TYPE' },
  CreateDomainStmt: { kind: 'ddl', command: 'CREATE DOMAIN' },
  AlterDomainStmt: { kind: 'ddl', command: 'ALTER DOMAIN' },
  DefineStmt: { kind: 'ddl', command: 'CREATE' },
  CreateFunctionStmt: { kind: 'ddl', command: 'CREATE FUNCTION' },
  AlterFunctionStmt: { kind: 'ddl', command: 'ALTER FUNCTION' },
  CreateTrigStmt: { kind: 'ddl', command: 'CREATE TRIGGER' },
  RuleStmt: { kind: 'ddl', command: 'CREATE RULE' },
  CreatePolicyStmt: { kind: 'ddl', command: 'CREATE POLICY' },
  AlterPolicyStmt: { kind: 'ddl', command: 'ALTER POLICY' },
  CreateSchemaStmt: { kind: 'ddl', command: 'CREATE SCHEMA' },
  AlterObjectSchemaStmt: { kind: 'ddl', command: 'ALTER … SET SCHEMA' },
  AlterOwnerStmt: { kind: 'ddl', command: 'ALTER … OWNER' },
  CreateStatsStmt: { kind: 'ddl', command: 'CREATE STATISTICS' },
  AlterStatsStmt: { kind: 'ddl', command: 'ALTER STATISTICS' },
  CreateConversionStmt: { kind: 'ddl', command: 'CREATE CONVERSION' },
  AlterTypeStmt: { kind: 'ddl', command: 'ALTER TYPE' },
  CreateForeignTableStmt: { kind: 'ddl', command: 'CREATE FOREIGN TABLE' },
  // admin
  GrantStmt: { kind: 'admin', command: 'GRANT' },
  GrantRoleStmt: { kind: 'admin', command: 'GRANT ROLE' },
  AlterDefaultPrivilegesStmt: { kind: 'admin', command: 'ALTER DEFAULT PRIVILEGES' },
  CreateRoleStmt: { kind: 'admin', command: 'CREATE ROLE' },
  AlterRoleStmt: { kind: 'admin', command: 'ALTER ROLE' },
  AlterRoleSetStmt: { kind: 'admin', command: 'ALTER ROLE SET' },
  DropRoleStmt: { kind: 'admin', command: 'DROP ROLE' },
  ReassignOwnedStmt: { kind: 'admin', command: 'REASSIGN OWNED' },
  DropOwnedStmt: { kind: 'admin', command: 'DROP OWNED' },
  AlterSystemStmt: { kind: 'admin', command: 'ALTER SYSTEM' },
  LoadStmt: { kind: 'admin', command: 'LOAD' },
  CreateExtensionStmt: { kind: 'admin', command: 'CREATE EXTENSION' },
  AlterExtensionStmt: { kind: 'admin', command: 'ALTER EXTENSION' },
  AlterExtensionContentsStmt: { kind: 'admin', command: 'ALTER EXTENSION' },
  CreatedbStmt: { kind: 'admin', command: 'CREATE DATABASE' },
  AlterDatabaseStmt: { kind: 'admin', command: 'ALTER DATABASE' },
  AlterDatabaseSetStmt: { kind: 'admin', command: 'ALTER DATABASE SET' },
  AlterDatabaseRefreshCollStmt: { kind: 'admin', command: 'ALTER DATABASE' },
  DropdbStmt: { kind: 'admin', command: 'DROP DATABASE' },
  CreateFdwStmt: { kind: 'admin', command: 'CREATE FOREIGN DATA WRAPPER' },
  AlterFdwStmt: { kind: 'admin', command: 'ALTER FOREIGN DATA WRAPPER' },
  CreateForeignServerStmt: { kind: 'admin', command: 'CREATE SERVER' },
  AlterForeignServerStmt: { kind: 'admin', command: 'ALTER SERVER' },
  CreateUserMappingStmt: { kind: 'admin', command: 'CREATE USER MAPPING' },
  AlterUserMappingStmt: { kind: 'admin', command: 'ALTER USER MAPPING' },
  DropUserMappingStmt: { kind: 'admin', command: 'DROP USER MAPPING' },
  ImportForeignSchemaStmt: { kind: 'admin', command: 'IMPORT FOREIGN SCHEMA' },
  CreatePublicationStmt: { kind: 'admin', command: 'CREATE PUBLICATION' },
  AlterPublicationStmt: { kind: 'admin', command: 'ALTER PUBLICATION' },
  CreateSubscriptionStmt: { kind: 'admin', command: 'CREATE SUBSCRIPTION' },
  AlterSubscriptionStmt: { kind: 'admin', command: 'ALTER SUBSCRIPTION' },
  DropSubscriptionStmt: { kind: 'admin', command: 'DROP SUBSCRIPTION' },
  CreateEventTrigStmt: { kind: 'admin', command: 'CREATE EVENT TRIGGER' },
  AlterEventTrigStmt: { kind: 'admin', command: 'ALTER EVENT TRIGGER' },
  CreateTableSpaceStmt: { kind: 'admin', command: 'CREATE TABLESPACE' },
  DropTableSpaceStmt: { kind: 'admin', command: 'DROP TABLESPACE' },
  AlterTableSpaceOptionsStmt: { kind: 'admin', command: 'ALTER TABLESPACE' },
  AlterTableMoveAllStmt: { kind: 'admin', command: 'ALTER TABLE … SET TABLESPACE' },
  SecLabelStmt: { kind: 'admin', command: 'SECURITY LABEL' },
  CreateAmStmt: { kind: 'admin', command: 'CREATE ACCESS METHOD' },
  CreateCastStmt: { kind: 'admin', command: 'CREATE CAST' },
  CreateTransformStmt: { kind: 'admin', command: 'CREATE TRANSFORM' },
  CreatePLangStmt: { kind: 'admin', command: 'CREATE LANGUAGE' },
  CreateOpClassStmt: { kind: 'admin', command: 'CREATE OPERATOR CLASS' },
  CreateOpFamilyStmt: { kind: 'admin', command: 'CREATE OPERATOR FAMILY' },
  AlterOpFamilyStmt: { kind: 'admin', command: 'ALTER OPERATOR FAMILY' },
  AlterCollationStmt: { kind: 'admin', command: 'ALTER COLLATION' },
  VacuumStmt: { kind: 'admin', command: 'VACUUM/ANALYZE' },
  ReindexStmt: { kind: 'admin', command: 'REINDEX' },
  ClusterStmt: { kind: 'admin', command: 'CLUSTER' },
  CheckPointStmt: { kind: 'admin', command: 'CHECKPOINT' },
  DoStmt: { kind: 'admin', command: 'DO' },
};

const WRITE_VERBS: Record<string, Verb> = { TruncateStmt: 'truncate', LockStmt: 'lock', NotifyStmt: 'notify', CallStmt: 'call', RefreshMatViewStmt: 'refresh' };

/** The verb of a mapped statement: writes by type, DDL by its leading keyword, admin is just admin. */
function verbFor(type: string, kind: Operation, command: string): Verb {
  if (kind === 'write') return WRITE_VERBS[type] ?? 'update';
  if (kind === 'ddl') return command.startsWith('CREATE') ? 'create' : command.startsWith('DROP') ? 'drop' : 'alter';
  return kind === 'read' ? 'select' : 'admin';
}

const nodeType = (n: Node) => Object.keys(n)[0];

/** `{relname, schemaname}` → `schema.table` / `table`. */
function rangeVarName(rv: Node): string {
  return rv.schemaname ? `${rv.schemaname}.${rv.relname}` : rv.relname;
}

function stringList(items: Node[] | undefined): string[] {
  return (items ?? []).map((i) => i.String?.sval ?? '').filter(Boolean);
}

/** A protobuf-style boolean: absent means false, `{}` means false, `{boolval: true}` means true. */
function boolArg(arg: Node | undefined): boolean | undefined {
  if (!arg) return undefined;
  if ('Boolean' in arg) return !!arg.Boolean.boolval;
  if ('A_Const' in arg) {
    const c = arg.A_Const;
    if ('boolval' in c) return !!c.boolval.boolval;
    if ('sval' in c) return !['false', 'off', '0', 'no'].includes(String(c.sval.sval).toLowerCase());
    if ('ival' in c) return (c.ival.ival ?? 0) !== 0;
  }
  if ('String' in arg) return !['false', 'off', '0', 'no'].includes(String(arg.String.sval).toLowerCase());
  if ('Integer' in arg) return (arg.Integer.ival ?? 0) !== 0;
  return true;
}

function constText(arg: Node | undefined): string | null {
  const c = arg?.A_Const;
  if (!c) return null;
  if ('sval' in c) return String(c.sval.sval ?? '');
  if ('ival' in c) return String(c.ival.ival ?? 0);
  if ('boolval' in c) return String(!!c.boolval.boolval);
  return null;
}

class Collector {
  accesses: Access[] = [];
  flags = new Set<string>();
  ctes = new Set<string>();
  reasons: string[] = [];

  constructor(private catalog: FunctionCatalog | null) {}

  table(rv: Node | undefined, op: Operation, verb: Verb) {
    if (!rv?.relname) return;
    // An unqualified read of a CTE name is the CTE, not a table.
    if (op === 'read' && !rv.schemaname && this.ctes.has(rv.relname)) return;
    this.accesses.push({ op, verb, table: rangeVarName(rv) });
  }

  plain(op: Operation, verb: Verb, reason?: string) {
    this.accesses.push({ op, verb, table: null });
    if (reason) this.reasons.push(reason);
  }

  func(funcname: Node[]) {
    const parts = stringList(funcname);
    if (parts.length === 0) return;
    const verdict = classifyFunction(parts, this.catalog);
    if (verdict.op !== 'read') this.plain(verdict.op, verdict.op === 'admin' ? 'admin' : 'function', verdict.reason);
  }

  /** Strictest operation seen. */
  strictest(fallback: Operation): Operation {
    return this.accesses.reduce<Operation>((k, a) => (OPERATION_RANK[a.op] > OPERATION_RANK[k] ? a.op : k), fallback);
  }
}

/**
 * Walks any expression/statement subtree. `op` is what a plain table reference here means
 * (read for queries, ddl/admin for the object a DDL/admin statement acts on).
 */
function walk(node: unknown, op: Operation, verb: Verb, c: Collector): void {
  if (Array.isArray(node)) {
    for (const n of node) walk(n, op, verb, c);
    return;
  }
  if (!node || typeof node !== 'object') return;
  for (const [type, body] of Object.entries(node as Node)) {
    if (!body || typeof body !== 'object') continue;
    // Single-table fields (e.g. AlterTableStmt.relation) hold the RangeVar unwrapped; list items are wrapped.
    if (type !== 'RangeVar' && typeof body.relname === 'string') {
      c.table(body, op, verb);
      continue;
    }
    switch (type) {
      case 'RangeVar':
        c.table(body, op, verb);
        break;
      case 'FuncCall':
        c.func(body.funcname);
        walk(body.args, 'read', 'select', c);
        walk(body.agg_filter, 'read', 'select', c);
        walk(body.over, 'read', 'select', c);
        walk(body.agg_order, 'read', 'select', c);
        break;
      case 'WithClause':
        for (const cte of body.ctes ?? []) if (cte.CommonTableExpr?.ctename) c.ctes.add(cte.CommonTableExpr.ctename);
        walk(body.ctes, 'read', 'select', c);
        break;
      case 'SelectStmt':
        walkSelect(body, c);
        break;
      case 'InsertStmt':
      case 'UpdateStmt':
      case 'DeleteStmt':
      case 'MergeStmt':
        walkDml(type, body, c);
        break;
      default:
        walk(body, op, verb, c);
    }
  }
}

function walkSelect(s: Node, c: Collector) {
  if (s.withClause) walk({ WithClause: s.withClause }, 'read', 'select', c);
  // FOR UPDATE / FOR SHARE takes row locks: treat the locked tables as written.
  const locks = !!s.lockingClause?.length;
  if (locks) c.flags.add('row_locks');
  if (s.intoClause) {
    c.table(s.intoClause.rel, 'ddl', 'create');
    c.flags.add('select_into');
  }
  walk(s.fromClause, locks ? 'write' : 'read', locks ? 'lock' : 'select', c);
  const { withClause: _w, fromClause: _f, intoClause: _i, lockingClause: _l, ...rest } = s;
  walk(rest, 'read', 'select', c);
}

const DML_VERBS: Record<string, Verb> = { InsertStmt: 'insert', UpdateStmt: 'update', DeleteStmt: 'delete', MergeStmt: 'merge' };

function walkDml(type: string, s: Node, c: Collector) {
  if (s.withClause) walk({ WithClause: s.withClause }, 'read', 'select', c);
  const verb = DML_VERBS[type];
  c.table(s.relation, 'write', verb);
  // INSERT … ON CONFLICT DO UPDATE can change existing rows: it is an update too.
  if (s.onConflictClause?.action === 'ONCONFLICT_UPDATE') c.table(s.relation, 'write', 'update');
  if ((type === 'UpdateStmt' || type === 'DeleteStmt') && !s.whereClause) c.flags.add('no_where');
  const { withClause: _w, relation: _r, ...rest } = s;
  walk(rest, 'read', 'select', c);
}

const TXN_COMMANDS: Record<string, string> = {
  TRANS_STMT_BEGIN: 'BEGIN',
  TRANS_STMT_START: 'BEGIN',
  TRANS_STMT_COMMIT: 'COMMIT',
  TRANS_STMT_ROLLBACK: 'ROLLBACK',
  TRANS_STMT_SAVEPOINT: 'SAVEPOINT',
  TRANS_STMT_RELEASE: 'RELEASE',
  TRANS_STMT_ROLLBACK_TO: 'ROLLBACK TO SAVEPOINT',
  TRANS_STMT_PREPARE: 'PREPARE TRANSACTION',
  TRANS_STMT_COMMIT_PREPARED: 'COMMIT PREPARED',
  TRANS_STMT_ROLLBACK_PREPARED: 'ROLLBACK PREPARED',
};

/** `READ WRITE` in BEGIN / SET TRANSACTION would undo read-only enforcement for read-only clients. */
function requestsReadWrite(options: Node[] | undefined): boolean {
  return (options ?? []).some((o) => o.DefElem?.defname === 'transaction_read_only' && boolArg(o.DefElem.arg) === false);
}

type Partial = Omit<StatementAnalysis, 'text'>;

function result(command: string, c: Collector, base: Operation, baseVerb: Verb, extraFlags: string[] = []): Partial {
  const kind = c.strictest(base);
  // Every statement records its own operation even when it touches no table (e.g. SELECT 1).
  if (!c.accesses.some((a) => a.op === base)) c.accesses.unshift({ op: base, verb: baseVerb, table: null });
  return { command, kind, accesses: dedupe(c.accesses), flags: [...new Set([...c.flags, ...extraFlags])] };
}

function dedupe(accesses: Access[]): Access[] {
  const seen = new Set<string>();
  return accesses.filter((a) => {
    const k = `${a.op}:${a.verb}:${a.table ?? ''}`;
    return seen.has(k) ? false : (seen.add(k), true);
  });
}

function session(command: string, flags: string[] = []): Partial {
  return { command, kind: 'session', accesses: [], flags };
}

function admin(command: string, reason: string): Partial {
  return { command, kind: 'admin', accesses: [{ op: 'admin', verb: 'admin', table: null }], flags: [reason] };
}

function classify(stmt: Node, ctx: AnalyzeContext): Partial {
  const type = nodeType(stmt);
  const s = stmt[type];
  const c = new Collector(ctx.catalog ?? null);

  switch (type) {
    case 'SelectStmt': {
      walkSelect(s, c);
      const base: Operation = s.intoClause ? 'ddl' : 'read';
      return result(s.intoClause ? 'SELECT INTO' : 'SELECT', c, base, s.intoClause ? 'create' : 'select');
    }
    case 'InsertStmt':
    case 'UpdateStmt':
    case 'DeleteStmt':
    case 'MergeStmt': {
      walkDml(type, s, c);
      return result(type.replace('Stmt', '').toUpperCase(), c, 'write', DML_VERBS[type]);
    }
    case 'ExplainStmt': {
      const analyze = (s.options ?? []).some((o: Node) => o.DefElem?.defname === 'analyze' && boolArg(o.DefElem.arg) !== false);
      const inner = classify(s.query, ctx);
      if (analyze) {
        // EXPLAIN ANALYZE executes the statement: it is exactly as dangerous as the statement.
        return { ...inner, command: `EXPLAIN ANALYZE ${inner.command}`, flags: [...inner.flags, 'explain_analyze'] };
      }
      // Plain EXPLAIN only plans: reads the catalog for every table the statement mentions.
      const tables = inner.accesses.filter((a) => a.table).map((a) => ({ op: 'read' as const, verb: 'select' as const, table: a.table }));
      return { command: `EXPLAIN ${inner.command}`, kind: 'read', accesses: dedupe([{ op: 'read', verb: 'select', table: null }, ...tables]), flags: [] };
    }
    case 'CopyStmt': {
      if (s.is_program || s.filename) return admin('COPY', s.is_program ? 'copy_program' : 'copy_server_file');
      if (s.is_from) {
        c.table(s.relation, 'write', 'insert');
        return result('COPY FROM STDIN', c, 'write', 'insert', ['copy']);
      }
      if (s.query) walk(s.query, 'read', 'select', c);
      else c.table(s.relation, 'read', 'select');
      return result('COPY TO STDOUT', c, 'read', 'select', ['copy']);
    }
    case 'DeclareCursorStmt': {
      const inner = classify(s.query, ctx);
      return { ...inner, command: `DECLARE CURSOR (${inner.command})` };
    }
    case 'FetchStmt':
      return session(s.ismove ? 'MOVE' : 'FETCH');
    case 'ClosePortalStmt':
      return session('CLOSE');
    case 'VariableShowStmt':
      return { command: 'SHOW', kind: 'read', accesses: [{ op: 'read', verb: 'select', table: null }], flags: [] };
    case 'VariableSetStmt': {
      const name = String(s.name ?? '').toLowerCase();
      const flags = s.is_local ? ['set_local'] : ['session_setting'];
      if (s.kind === 'VAR_RESET_ALL') return session('RESET ALL', flags);
      if (s.kind === 'VAR_SET_MULTI') {
        // SET TRANSACTION … / SET SESSION CHARACTERISTICS AS TRANSACTION …
        if (name === 'transaction' && !requestsReadWrite(s.args)) return session('SET TRANSACTION', flags);
        return admin(name === 'transaction' ? 'SET TRANSACTION READ WRITE' : 'SET SESSION CHARACTERISTICS', 'privileged_setting');
      }
      if (!SESSION_SETTINGS.has(name)) return admin(`SET ${name}`, 'privileged_setting');
      if (name === 'client_encoding') {
        const v = constText(s.args?.[0])?.toLowerCase().replace(/[-_]/g, '');
        if (s.kind === 'VAR_SET_VALUE' && v !== 'utf8') return admin('SET client_encoding', 'non_utf8_encoding');
      }
      return session(`${s.kind === 'VAR_RESET' ? 'RESET' : 'SET'} ${name}`, flags);
    }
    case 'TransactionStmt': {
      const command = TXN_COMMANDS[s.kind] ?? 'TRANSACTION';
      if (['TRANS_STMT_PREPARE', 'TRANS_STMT_COMMIT_PREPARED', 'TRANS_STMT_ROLLBACK_PREPARED'].includes(s.kind)) {
        return admin(command, 'two_phase_commit');
      }
      if (requestsReadWrite(s.options)) return admin(`${command} READ WRITE`, 'privileged_setting');
      return session(command, ['transaction_control']);
    }
    case 'ConstraintsSetStmt':
      return session('SET CONSTRAINTS');
    case 'DeallocateStmt':
      return session('DEALLOCATE', ['prepared_statement']);
    case 'DiscardStmt':
      return session('DISCARD', ['session_reset']);
    case 'ListenStmt':
      return session('LISTEN', ['listen']);
    case 'UnlistenStmt':
      return session('UNLISTEN', ['listen']);
    case 'PrepareStmt': {
      const inner = classify(s.query, ctx);
      const text = ''; // filled by caller via the outer statement's text
      return { command: 'PREPARE', kind: 'session', accesses: [], flags: ['prepared_statement'], prepared: { name: s.name, analysis: { text, ...inner } } };
    }
    case 'ExecuteStmt': {
      const prepared = ctx.prepared?.get(s.name);
      if (!prepared) return admin('EXECUTE', 'unknown_prepared_statement');
      return { ...prepared, command: `EXECUTE (${prepared.command})`, flags: [...prepared.flags, 'prepared_statement'] };
    }
    case 'DropStmt': {
      const k = STATEMENT_KINDS.DropStmt;
      const tableLike = ['OBJECT_TABLE', 'OBJECT_VIEW', 'OBJECT_MATVIEW', 'OBJECT_FOREIGN_TABLE', 'OBJECT_SEQUENCE', 'OBJECT_INDEX'];
      if (tableLike.includes(s.removeType)) {
        for (const obj of s.objects ?? []) {
          const parts = stringList(obj.List?.items);
          if (parts.length) c.accesses.push({ op: 'ddl', verb: 'drop', table: parts.join('.') });
        }
      }
      const flags = ['destructive', ...(s.concurrent ? ['no_transaction'] : [])];
      return result(`DROP ${String(s.removeType ?? '').replace('OBJECT_', '').replace('_', ' ')}`.trim(), c, k.kind, 'drop', flags);
    }
    case 'TruncateStmt': {
      for (const r of s.relations ?? []) c.table(r.RangeVar, 'write', 'truncate');
      return result('TRUNCATE', c, 'write', 'truncate', ['destructive']);
    }
    case 'ViewStmt': {
      c.table(s.view, 'ddl', 'create');
      walk(s.query, 'read', 'select', c);
      return result(STATEMENT_KINDS.ViewStmt.command, c, 'ddl', 'create');
    }
    case 'CreateTableAsStmt': {
      c.table(s.into?.rel, 'ddl', 'create');
      walk(s.query, 'read', 'select', c);
      return result(s.objtype === 'OBJECT_MATVIEW' ? 'CREATE MATERIALIZED VIEW' : 'CREATE TABLE AS', c, 'ddl', 'create');
    }
    case 'IndexStmt': {
      c.table(s.relation, 'ddl', 'create');
      walk(s.whereClause, 'read', 'select', c);
      walk(s.indexParams, 'read', 'select', c);
      return result('CREATE INDEX', c, 'ddl', 'create', s.concurrent ? ['no_transaction'] : []);
    }
    case 'VacuumStmt': {
      for (const r of s.rels ?? []) c.table(r.VacuumRelation?.relation, 'admin', 'admin');
      return result(s.is_vacuumcmd ? 'VACUUM' : 'ANALYZE', c, 'admin', 'admin', ['no_transaction']);
    }
    case 'ReindexStmt': {
      c.table(s.relation, 'admin', 'admin');
      return result('REINDEX', c, 'admin', 'admin', ['no_transaction']);
    }
  }

  const mapped = STATEMENT_KINDS[type];
  if (!mapped) return admin(type.replace(/Stmt$/, '').toUpperCase(), 'unrecognized_statement');
  // Generic: the objects a DDL/admin statement names get its operation; subqueries in it are reads.
  const verb = verbFor(type, mapped.kind, mapped.command);
  walk(s, mapped.kind, verb, c);
  return result(mapped.command, c, mapped.kind, verb);
}

/** Byte offsets from the parser index UTF-8 bytes; slice on bytes, not UTF-16 code units. */
function sliceStatement(sqlBytes: Buffer, loc: number | undefined, len: number | undefined): string {
  const start = loc ?? 0;
  const end = len ? start + len : sqlBytes.length;
  return sqlBytes.subarray(start, end).toString('utf8').trim();
}

export function analyze(sql: string, ctx: AnalyzeContext = {}): Analysis {
  let parsed: { stmts?: { stmt: Node; stmt_location?: number; stmt_len?: number }[] };
  try {
    parsed = parseSync(sql) as any;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      statements: [{ text: sql.trim(), command: 'UNPARSEABLE', kind: 'admin', accesses: [{ op: 'admin', verb: 'admin', table: null }], flags: ['unparseable'] }],
      error: message,
    };
  }
  const bytes = Buffer.from(sql, 'utf8');
  // A PREPARE earlier in the same string is known to a later EXECUTE.
  const prepared = new Map(ctx.prepared);
  const statements = (parsed.stmts ?? []).map((raw) => {
    const text = sliceStatement(bytes, raw.stmt_location, raw.stmt_len);
    let partial: Partial;
    try {
      partial = classify(raw.stmt, { ...ctx, prepared });
    } catch {
      partial = admin('UNKNOWN', 'classification_failed');
    }
    if (partial.prepared) {
      partial.prepared.analysis.text = text;
      // Postgres refuses to PREPARE a name that exists, so an EXECUTE would still run the old one.
      if (!prepared.has(partial.prepared.name)) prepared.set(partial.prepared.name, partial.prepared.analysis);
    }
    return { text, ...partial };
  });
  return { statements, error: null };
}

/** Strictest operation across all statements (null if everything is session-level). */
export function strictestKind(analysis: Analysis): Operation | null {
  let best: Operation | null = null;
  for (const s of analysis.statements) {
    if (s.kind === 'session') continue;
    if (!best || OPERATION_RANK[s.kind] > OPERATION_RANK[best]) best = s.kind;
  }
  return best;
}
