/**
 * A MySQL/MariaDB lexer that sees SQL the way the server does: quotes, backslash escapes, the three
 * comment styles, and executable comments (`/*! … *\/`, `/*M! … *\/`), whose content the server runs
 * and so we classify. Classification works on these tokens rather than on a grammar, so syntax we
 * don't model can only make a statement look stricter, never hide part of it.
 */

export type TokenType = 'word' | 'ident' | 'string' | 'number' | 'var' | 'sysvar' | 'param' | 'punct';

export interface Token {
  type: TokenType;
  /** Unescaped value: identifier name, string contents, variable name, or the punctuation itself. */
  value: string;
  /** Uppercased value, for keyword checks on `word` tokens. */
  upper: string;
  start: number;
  end: number;
  /** For tokens inside an executable comment: where that comment starts and ends. */
  exec?: { start: number; end: number };
  /** Whitespace or a comment precedes this token. */
  spaced: boolean;
}

export interface LexOptions {
  /** sql_mode ANSI_QUOTES: "x" is an identifier, not a string. */
  ansiQuotes?: boolean;
  /** sql_mode NO_BACKSLASH_ESCAPES: backslash is an ordinary character in strings. */
  noBackslashEscapes?: boolean;
}

export class LexError extends Error {}

const isIdentStart = (c: string) => /[A-Za-z_$]/.test(c) || c.charCodeAt(0) >= 0x80;
const isIdentChar = (c: string) => /[A-Za-z0-9_$]/.test(c) || c.charCodeAt(0) >= 0x80;
const isDigit = (c: string) => c >= '0' && c <= '9';

const ESCAPES: Record<string, string> = { '0': '\0', "'": "'", '"': '"', b: '\b', n: '\n', r: '\r', t: '\t', Z: '\x1a', '\\': '\\' };

/** Multi-character operators, longest first. */
const OPERATORS = ['<=>', '->>', ':=', '<=', '>=', '<>', '!=', '<<', '>>', '&&', '||', '->'];

export function lex(sql: string, opts: LexOptions = {}): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  let spaced = true;
  let exec: { start: number; end: number } | null = null;
  const n = sql.length;

  const push = (type: TokenType, value: string, start: number) => {
    tokens.push({ type, value, upper: type === 'word' ? value.toUpperCase() : value, start, end: i, exec: exec ?? undefined, spaced });
    spaced = false;
  };

  /** Reads a quoted run starting at the opening quote; doubled quotes always escape, backslashes only in strings. */
  const quoted = (q: string, backslash: boolean): string => {
    let out = '';
    i++;
    for (;;) {
      if (i >= n) throw new LexError(`unterminated ${q} quote`);
      const c = sql[i];
      if (c === q) {
        if (sql[i + 1] === q) {
          out += q;
          i += 2;
          continue;
        }
        i++;
        return out;
      }
      if (backslash && c === '\\' && i + 1 < n) {
        const e = sql[i + 1];
        // \% and \_ keep their backslash (LIKE escapes); unknown escapes drop it.
        out += e === '%' || e === '_' ? `\\${e}` : (ESCAPES[e] ?? e);
        i += 2;
        continue;
      }
      out += c;
      i++;
    }
  };

  while (i < n) {
    const c = sql[i];
    const start = i;

    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === '\f' || c === '\v') {
      i++;
      spaced = true;
      continue;
    }
    // `-- ` comments need whitespace or a control character after the dashes (MySQL rule); `--1` is minus minus one.
    if (c === '-' && sql[i + 1] === '-' && (i + 2 >= n || sql.charCodeAt(i + 2) <= 0x20)) {
      while (i < n && sql[i] !== '\n') i++;
      spaced = true;
      continue;
    }
    if (c === '#') {
      while (i < n && sql[i] !== '\n') i++;
      spaced = true;
      continue;
    }
    if (c === '/' && sql[i + 1] === '*') {
      const execMatch = /^\/\*(M?)!(\d{5,6})?/.exec(sql.slice(i, i + 10));
      if (execMatch) {
        if (exec) throw new LexError('nested executable comment');
        const close = sql.indexOf('*/', i + execMatch[0].length);
        exec = { start: i, end: close < 0 ? n : close + 2 };
        i += execMatch[0].length;
        spaced = true;
        continue;
      }
      const close = sql.indexOf('*/', i + 2);
      if (close < 0) throw new LexError('unterminated comment');
      i = close + 2;
      spaced = true;
      continue;
    }
    if (exec && c === '*' && sql[i + 1] === '/') {
      i += 2;
      exec = null;
      spaced = true;
      continue;
    }
    if (c === "'") {
      push('string', quoted("'", !opts.noBackslashEscapes), start);
      continue;
    }
    if (c === '"') {
      if (opts.ansiQuotes) push('ident', quoted('"', false), start);
      else push('string', quoted('"', !opts.noBackslashEscapes), start);
      continue;
    }
    if (c === '`') {
      push('ident', quoted('`', false), start);
      continue;
    }
    if (c === '@') {
      if (sql[i + 1] === '@') {
        i += 2;
        // @@global.name, @@session.name, @@name — keep the whole dotted name.
        const m = /^[A-Za-z0-9_$.]+/.exec(sql.slice(i));
        if (m) i += m[0].length;
        else if (sql[i] === '`') quoted('`', false);
        push('sysvar', sql.slice(start + 2, i), start);
        continue;
      }
      i++;
      const q = sql[i];
      if (q === "'" || q === '"' || q === '`') {
        push('var', quoted(q, q !== '`' && !opts.noBackslashEscapes), start);
        continue;
      }
      const m = /^[A-Za-z0-9_$.]*/.exec(sql.slice(i))!;
      i += m[0].length;
      push('var', m[0], start);
      continue;
    }
    if (c === '?') {
      i++;
      push('param', '?', start);
      continue;
    }
    if (isDigit(c) || (c === '.' && isDigit(sql[i + 1] ?? ''))) {
      // 0x1F, 0b101, 1.5e3 — but 1abc is an identifier.
      const m = /^(0x[0-9A-Fa-f]+|0b[01]+|\d*\.?\d+(?:[eE][+-]?\d+)?|\d+\.?)/.exec(sql.slice(i))!;
      const after = sql[i + m[0].length] ?? '';
      if (isIdentChar(after) && !m[0].includes('.')) {
        while (i < n && isIdentChar(sql[i])) i++;
        push('word', sql.slice(start, i), start);
      } else {
        i += m[0].length;
        push('number', m[0], start);
      }
      continue;
    }
    if (isIdentStart(c)) {
      while (i < n && isIdentChar(sql[i])) i++;
      push('word', sql.slice(start, i), start);
      continue;
    }
    const op = OPERATORS.find((o) => sql.startsWith(o, i));
    if (op) {
      i += op.length;
      push('punct', op, start);
      continue;
    }
    i++;
    push('punct', c, start);
  }
  return tokens;
}

/** The source text a token range covers, widened to include any executable comment it starts or ends inside. */
export function sliceTokens(sql: string, tokens: Token[]): string {
  if (tokens.length === 0) return '';
  const first = tokens[0];
  const last = tokens[tokens.length - 1];
  const start = first.exec ? Math.min(first.exec.start, first.start) : first.start;
  const end = last.exec ? Math.max(last.exec.end, last.end) : last.end;
  return sql.slice(start, end).trim();
}
