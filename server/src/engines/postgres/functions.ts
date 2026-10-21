import type { Operation } from '../types.js';

/**
 * Function calls inside otherwise read-only statements are the main way a "SELECT" can have side
 * effects. Classification, in order:
 *   1. explicit denylist → admin (backend control, server files, dblink, SQL-in-a-string, …)
 *   2. explicit write list → write (sequences, NOTIFY, advisory locks)
 *   3. non-core/unknown functions → opaque (never executed through the proxy)
 *   4. verified core functions: known harmless volatile calls → read; other volatile calls → write
 * STABLE/IMMUTABLE user functions may invoke writing VOLATILE functions, so their volatility
 * declarations are not a safety boundary.
 */

const DENY_EXACT = new Set([
  'pg_terminate_backend',
  'pg_cancel_backend',
  'pg_reload_conf',
  'pg_rotate_logfile',
  'pg_promote',
  'pg_switch_wal',
  'pg_create_restore_point',
  'pg_log_backend_memory_contexts',
  'set_config',
  'pg_read_file',
  'pg_read_binary_file',
  'pg_stat_file',
  'pg_import_system_collations',
  // Execute SQL passed as a string, or read a table named by a string — escapes table rules.
  'query_to_xml',
  'query_to_xmlschema',
  'query_to_xml_and_xmlschema',
  'cursor_to_xml',
  'cursor_to_xmlschema',
  'table_to_xml',
  'table_to_xmlschema',
  'table_to_xml_and_xmlschema',
  'ts_stat',
]);

const DENY_PATTERNS = [/^pg_ls_/, /^lo_/, /^dblink/, /^pg_backup_/, /^pg_logical_/, /replication_slot/, /^pg_wal_replay_/, /^pg_file_/, /^pg_stat_reset/];

const WRITE_EXACT = new Set(['nextval', 'setval', 'pg_notify']);
const WRITE_PATTERNS = [/^pg_(try_)?advisory_(xact_)?lock(_shared)?$/, /^pg_advisory_unlock/];

const SAFE_VOLATILE = new Set([
  'random',
  'random_normal',
  'gen_random_uuid',
  'uuid_generate_v4',
  'clock_timestamp',
  'timeofday',
  'pg_sleep',
  'pg_sleep_for',
  'pg_sleep_until',
  'txid_current',
  'txid_current_if_assigned',
  'pg_current_xact_id',
  'pg_current_xact_id_if_assigned',
]);

/**
 * Used only when no catalog snapshot is available (e.g. unit tests, catalog load failure):
 * common non-volatile built-ins, so ordinary SELECTs don't all turn into writes.
 */
const FALLBACK_NON_VOLATILE = new Set(
  (
    'count sum avg min max lower upper length char_length octet_length substring substr btrim ltrim rtrim trim ' +
    'replace split_part concat concat_ws format left right lpad rpad position strpos regexp_replace regexp_match ' +
    'regexp_matches starts_with now date_trunc date_part extract to_char to_date to_timestamp to_number age ' +
    'make_date make_interval round floor ceil ceiling abs mod power sqrt greatest least coalesce nullif ' +
    'string_agg array_agg json_agg jsonb_agg json_build_object jsonb_build_object json_object_agg jsonb_object_agg ' +
    'jsonb_build_array json_build_array to_json to_jsonb jsonb_set jsonb_extract_path jsonb_array_length ' +
    'array_length cardinality unnest generate_series row_number rank dense_rank percent_rank lag lead first_value ' +
    'last_value ntile bool_and bool_or every md5 encode decode current_setting version pg_typeof ' +
    'pg_size_pretty pg_total_relation_size pg_relation_size pg_table_size pg_indexes_size pg_get_viewdef ' +
    'pg_get_indexdef pg_get_constraintdef format_type obj_description col_description to_regclass'
  ).split(' '),
);

/** Core volatility, or opaque if any overload is supplied outside PostgreSQL core. */
export type FunctionCatalog = Map<string, boolean | 'opaque'>;

export interface FunctionVerdict {
  op: Operation;
  reason: string;
  opaque?: boolean;
}

export function classifyFunction(nameParts: string[], catalog: FunctionCatalog | null): FunctionVerdict {
  const name = nameParts[nameParts.length - 1].toLowerCase();
  const schema = nameParts.length > 1 ? nameParts[nameParts.length - 2].toLowerCase() : null;
  const qualified = schema ? `${schema}.${name}` : name;

  // set_config could otherwise disable enforced timeouts or change parser/privilege settings.
  if (name === 'set_config') return { op: 'admin', reason: 'set_config() bypasses session safeguards', opaque: true };
  if (DENY_EXACT.has(name) || DENY_PATTERNS.some((p) => p.test(name))) return { op: 'admin', reason: `${qualified}() is a privileged function` };
  const exactKey = schema ? qualified : name;
  if (catalog) {
    const volatile = catalog.get(exactKey);
    if (volatile === 'opaque' || volatile === undefined) return { op: 'write', reason: `${qualified}() has uninspectable effects`, opaque: true };
    if (WRITE_EXACT.has(name) || WRITE_PATTERNS.some((p) => p.test(name))) return { op: 'write', reason: `${qualified}() has side effects` };
    if ((!schema || schema === 'pg_catalog') && SAFE_VOLATILE.has(name)) return { op: 'read', reason: '' };
    return volatile ? { op: 'write', reason: `${qualified}() is volatile and may modify data` } : { op: 'read', reason: '' };
  }
  if ((!schema || schema === 'pg_catalog') && (WRITE_EXACT.has(name) || WRITE_PATTERNS.some((p) => p.test(name)))) return { op: 'write', reason: `${qualified}() has side effects` };
  if ((!schema || schema === 'pg_catalog') && SAFE_VOLATILE.has(name)) return { op: 'read', reason: '' };
  if ((!schema || schema === 'pg_catalog') && FALLBACK_NON_VOLATILE.has(name)) return { op: 'read', reason: '' };
  return { op: 'write', reason: `${qualified}() may have side effects`, opaque: true };
}
