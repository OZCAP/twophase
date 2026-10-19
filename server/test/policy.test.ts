import { describe, expect, it } from 'vitest';
import { canOnlyRead, decideAccess, evaluateAnalysis, grantsCover, tableMatches } from '../src/policy.js';
import type { DatabaseConfig, Grant, Rule } from '../src/store.js';

const db = { id: 'd', defaultRead: 'allow', defaultWrite: 'approve', defaultDdl: 'approve', defaultAdmin: 'deny' } as DatabaseConfig;
let n = 0;
const rule = (operation: Rule['operation'], action: Rule['action'], tablePattern: string | null = null, userId: string | null = null): Rule => ({
  id: `r${++n}`,
  databaseId: 'd',
  userId,
  operation,
  tablePattern,
  action,
  note: null,
  createdAt: new Date(0),
});

describe('tableMatches', () => {
  it('matches full and bare names, globs, and treats null as any table', () => {
    expect(tableMatches('orders', 'orders')).toBe(true);
    expect(tableMatches('orders', 'public.orders')).toBe(true);
    expect(tableMatches('public.orders', 'orders')).toBe(false);
    expect(tableMatches('audit_*', 'app.audit_log')).toBe(true);
    expect(tableMatches('app.*', 'app.orders')).toBe(true);
    expect(tableMatches(null, null)).toBe(true);
    expect(tableMatches('orders', null)).toBe(false);
  });
});

describe('decideAccess', () => {
  it('falls back to the per-operation default', () => {
    expect(decideAccess([], db, 'u', { op: 'read', verb: 'select', table: 'orders' }).action).toBe('allow');
    expect(decideAccess([], db, 'u', { op: 'write', verb: 'update', table: 'orders' }).action).toBe('approve');
    expect(decideAccess([], db, 'u', { op: 'admin', verb: 'admin', table: null }).action).toBe('deny');
  });

  it('client-specific beats everyone; exact table beats glob beats any; ties go stricter', () => {
    const rules = [rule('write', 'deny'), rule('write', 'allow', 'orders'), rule('write', 'approve', null, 'u1'), rule('write', 'deny', 'orders', 'u1'), rule('write', 'allow', 'ord*'), rule('write', 'approve', 'ord*')];
    expect(decideAccess(rules, db, 'u2', { op: 'write', verb: 'update', table: 'orders' }).action).toBe('allow');
    expect(decideAccess(rules, db, 'u2', { op: 'write', verb: 'update', table: 'ordinals' }).action).toBe('approve');
    expect(decideAccess(rules, db, 'u2', { op: 'write', verb: 'update', table: 'customers' }).action).toBe('deny');
    expect(decideAccess(rules, db, 'u1', { op: 'write', verb: 'update', table: 'customers' }).action).toBe('approve');
    expect(decideAccess(rules, db, 'u1', { op: 'write', verb: 'update', table: 'orders' }).action).toBe('deny');
  });

  it('table-specific rules never match table-less accesses', () => {
    expect(decideAccess([rule('write', 'allow', 'orders')], db, 'u', { op: 'write', verb: 'update', table: null }).action).toBe('approve');
  });
});

describe('verb-level rules', () => {
  const ins = { op: 'write' as const, verb: 'insert' as const, table: 'orders' };
  const del = { op: 'write' as const, verb: 'delete' as const, table: 'orders' };
  it('auto-approve inserts but keep asking for deletes', () => {
    const rules = [rule('insert', 'allow')];
    expect(decideAccess(rules, db, 'u', ins).action).toBe('allow');
    expect(decideAccess(rules, db, 'u', del).action).toBe('approve');
  });
  it('a verb rule beats a whole-operation rule at the same scope', () => {
    const rules = [rule('write', 'deny'), rule('insert', 'allow')];
    expect(decideAccess(rules, db, 'u', ins).action).toBe('allow');
    expect(decideAccess(rules, db, 'u', del).action).toBe('deny');
  });
  it('a table-scoped deny still wins over a broad verb allow (tie goes stricter)', () => {
    const rules = [rule('insert', 'allow'), rule('write', 'deny', 'audit_*')];
    expect(decideAccess(rules, db, 'u', { ...ins, table: 'audit_log' }).action).toBe('deny');
    expect(decideAccess(rules, db, 'u', ins).action).toBe('allow');
  });
  it('trust windows can be verb-specific', () => {
    const g = { id: 'g', databaseId: 'd', userId: 'u', operation: 'delete' as const, tablePattern: 'orders', expiresAt: null, approvalId: null, note: null, createdAt: new Date(0) };
    expect(grantsCover([g], 'u', [del])).toBe(true);
    expect(grantsCover([g], 'u', [{ ...del, verb: 'update' }])).toBe(false);
  });
  it('a client denied every write verb individually is still not "read-only" unless all are covered', () => {
    expect(canOnlyRead([rule('insert', 'deny', null, 'u'), rule('ddl', 'deny', null, 'u')], db, 'u')).toBe(false);
  });
});

describe('evaluateAnalysis', () => {
  it('takes the strictest decision across all statements and accesses', () => {
    const analysis = {
      error: null,
      statements: [
        { text: '', command: 'SELECT', kind: 'read' as const, flags: [], accesses: [{ op: 'read' as const, verb: 'select' as const, table: 'orders' }] },
        { text: '', command: 'DELETE', kind: 'write' as const, flags: [], accesses: [{ op: 'write' as const, verb: 'delete' as const, table: 'audit' }] },
      ],
    };
    expect(evaluateAnalysis([], db, 'u', analysis).action).toBe('approve');
    expect(evaluateAnalysis([rule('write', 'deny', 'audit')], db, 'u', analysis).action).toBe('deny');
  });
});

describe('grantsCover', () => {
  const grant = (operation: Grant['operation'], tablePattern: string | null, userId: string | null = 'u'): Grant => ({
    id: 'g', databaseId: 'd', userId, operation, tablePattern, expiresAt: null, approvalId: null, note: null, createdAt: new Date(0),
  });
  it('needs every asked access covered', () => {
    const asked = [{ op: 'write' as const, verb: 'update' as const, table: 'orders' }, { op: 'ddl' as const, verb: 'alter' as const, table: 'orders' }];
    expect(grantsCover([grant('write', 'orders')], 'u', asked)).toBe(false);
    expect(grantsCover([grant('write', 'orders'), grant('ddl', null)], 'u', asked)).toBe(true);
    expect(grantsCover([grant(null, null)], 'u', asked)).toBe(true);
    expect(grantsCover([grant(null, null, 'other')], 'u', asked)).toBe(false);
  });
});

describe('canOnlyRead', () => {
  it('is false under the defaults (writes ask)', () => {
    expect(canOnlyRead([], db, 'u')).toBe(false);
  });
  it('is true when client-specific denies cover write and ddl (admin is denied by default)', () => {
    expect(canOnlyRead([rule('write', 'deny', null, 'u'), rule('ddl', 'deny', null, 'u')], db, 'u')).toBe(true);
  });
  it('is false if any more specific rule could still allow a write', () => {
    const rules = [rule('write', 'deny', null, 'u'), rule('ddl', 'deny', null, 'u'), rule('write', 'allow', 'scratch', 'u')];
    expect(canOnlyRead(rules, db, 'u')).toBe(false);
  });
  it('an everyone-allow on a table is overridden by the client-specific any-table deny', () => {
    const rules = [rule('write', 'deny', null, 'u'), rule('ddl', 'deny', null, 'u'), rule('write', 'allow', 'orders')];
    expect(canOnlyRead(rules, db, 'u')).toBe(true);
  });
});
