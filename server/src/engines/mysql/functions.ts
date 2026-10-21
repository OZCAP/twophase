import type { Access } from '../types.js';

/**
 * Functions are how a MySQL "SELECT" can have side effects. Classification, in order:
 *   1. loadable UDFs (from the catalog) and server-file/shell functions → admin
 *   2. stored functions and unknown/schema-qualified calls → opaque. MySQL does not enforce
 *      READS SQL DATA / NO SQL, so a stored function's declared characteristics prove nothing.
 *   3. a short list of side-effecting built-ins (named locks, sequences) → write
 *   4. otherwise a built-in → read. Without a catalog, only names on the built-in list count as
 *      built-ins; anything else asks.
 */

export interface RoutineCatalog {
  /** Stored functions, lowercased: `db.name`, plus bare `name` for the current database. */
  functions: Set<string>;
  /** Loadable (CREATE FUNCTION … SONAME) functions, lowercased. */
  udfs: Set<string>;
}

const ADMIN = new Set(['load_file', 'sys_exec', 'sys_eval', 'sys_get', 'sys_set', 'lib_mysqludf_sys_info']);

const WRITE = new Set(['get_lock', 'release_lock', 'release_all_locks', 'nextval', 'setval']);

/** Built-in functions and the type names that appear as `name(` (CAST … AS CHAR(10)). */
const BUILTINS = new Set(
  `abs acos adddate addtime aes_decrypt aes_encrypt any_value ascii asin atan atan2 avg benchmark bin bin_to_uuid binary
  bit_and bit_count bit_length bit_or bit_xor cast ceil ceiling char char_length character_length charset coalesce
  coercibility collation compress concat concat_ws connection_id conv convert convert_tz cos cot count crc32 cume_dist
  curdate current_date current_role current_time current_timestamp current_user curtime database date date_add
  date_format date_sub datediff day dayname dayofmonth dayofweek dayofyear decode default degrees dense_rank des_decrypt
  des_encrypt elt encode encrypt exp export_set extract extractvalue field find_in_set first_value floor format
  format_bytes format_pico_time found_rows from_base64 from_days from_unixtime geomcollection geometrycollection
  get_format greatest group_concat grouping gtid_subset gtid_subtract hex hour icu_version if ifnull in inet_aton
  inet_ntoa inet6_aton inet6_ntoa insert instr interval is_free_lock is_ipv4 is_ipv4_compat is_ipv4_mapped is_ipv6
  is_used_lock is_uuid isnull json_array json_array_append json_array_insert json_arrayagg json_contains
  json_contains_path json_depth json_extract json_insert json_keys json_length json_merge json_merge_patch
  json_merge_preserve json_object json_objectagg json_overlaps json_pretty json_quote json_remove json_replace
  json_schema_valid json_schema_validation_report json_search json_set json_storage_free json_storage_size json_table
  json_type json_unquote json_valid json_value json_exists json_query json_compact json_detailed json_loose
  json_equals json_normalize lag last_day last_insert_id last_value lastval lcase lead least left length linestring ln
  load_file localtime localtimestamp locate log log10 log2 lower lpad ltrim make_set makedate maketime master_pos_wait
  match max mbrcontains mbrcoveredby mbrcovers mbrdisjoint mbrequals mbrintersects mbroverlaps mbrtouches mbrwithin md5
  microsecond mid min minute mod month monthname multilinestring multipoint multipolygon name_const now nth_value ntile
  nullif oct octet_length ord percent_rank period_add period_diff pi point polygon position pow power ps_current_thread_id
  ps_thread_id quarter quote radians rand random_bytes rank regexp_instr regexp_like regexp_replace regexp_substr
  release_all_locks release_lock repeat replace reverse right round row_count row_number rpad rtrim schema sec_to_time
  second session_user sha sha1 sha2 sign sin sleep soundex source_pos_wait space sqrt st_area st_asbinary st_asgeojson
  st_astext st_aswkb st_aswkt st_buffer st_centroid st_contains st_convexhull st_crosses st_difference st_dimension
  st_disjoint st_distance st_distance_sphere st_endpoint st_envelope st_equals st_exteriorring st_geomfromgeojson
  st_geomfromtext st_geomfromwkb st_intersection st_intersects st_isclosed st_isempty st_isvalid st_latitude st_length
  st_longitude st_numpoints st_overlaps st_pointn st_srid st_startpoint st_symdifference st_touches st_transform
  st_union st_within st_x st_y statement_digest statement_digest_text std stddev stddev_pop stddev_samp str_to_date
  strcmp subdate substr substring substring_index subtime sum sysdate system_user tan time time_format time_to_sec
  timediff timestamp timestampadd timestampdiff to_base64 to_days to_seconds trim truncate ucase uncompress
  uncompressed_length unhex unix_timestamp updatexml upper user utc_date utc_time utc_timestamp uuid uuid_short
  uuid_to_bin validate_password_strength values var_pop var_samp variance version wait_for_executed_gtid_set week
  weekday weekofyear weight_string year yearweek row exists not
  signed unsigned decimal dec numeric datetime double float real int integer tinyint smallint mediumint bigint bit bool
  boolean nchar varchar varbinary blob text tinytext mediumtext longtext tinyblob mediumblob longblob enum json
  natural_sort_key sformat chr to_char add_months json_array_intersect json_object_filter_keys json_object_to_array
  json_key_value kdf sys_guid uuid_v4 uuid_v7 crc32c format_bytes nvl nvl2 decode_oracle lastval`
    .split(/\s+/)
    .filter(Boolean),
);

export function isBuiltin(name: string): boolean {
  return BUILTINS.has(name.toLowerCase());
}

/**
 * What a call to `parts.join('.')` does; null for a plain read. `parts` is [name] or [db, name].
 */
export function classifyFunction(parts: string[], catalog: RoutineCatalog | null): (Access & { opaque?: boolean }) | null {
  const name = parts[parts.length - 1].toLowerCase();
  const qualified = parts.length > 1 ? `${parts[0].toLowerCase()}.${name}` : null;
  if (parts.length === 1 && catalog?.udfs.has(name)) return { op: 'admin', verb: 'admin', table: null, opaque: true };
  if (parts.length === 1 && ADMIN.has(name)) return { op: 'admin', verb: 'admin', table: null };
  if (qualified) return { op: 'write', verb: 'function', table: null, opaque: true };
  if (catalog?.functions.has(name)) return { op: 'write', verb: 'function', table: null, opaque: true };
  if (WRITE.has(name)) return { op: 'write', verb: 'function', table: null };
  if (BUILTINS.has(name)) return null;
  // Unknown metadata must never turn a function into a harmless session statement.
  return { op: 'write', verb: 'function', table: null, opaque: true };
}
