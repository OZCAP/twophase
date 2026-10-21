import { describe, expect, it } from 'vitest';
import { assertFixtureDatabaseEnvironment, FIXTURE_DATABASE_URLS } from './fixtures.js';

describe('database test isolation', () => {
  it('accepts defaults and the exact documented fixture URLs', () => {
    expect(() => assertFixtureDatabaseEnvironment({})).not.toThrow();
    expect(() => assertFixtureDatabaseEnvironment({ ...FIXTURE_DATABASE_URLS })).not.toThrow();
  });

  for (const [name, url] of Object.entries(FIXTURE_DATABASE_URLS)) {
    it.each([
      url.replace('127.0.0.1', 'database.example.com'),
      url.replace('127.0.0.1', '100.64.0.1'),
      url.replace('127.0.0.1', 'database.example.ts.net'),
      url.replace(/:\d+\//, ':5432/'),
      url.replace(/\/[^/]+$/, '/production'),
      url.replace(/\/\/[^@]+@/, '//real-user:private-fixture-sentinel@'),
      `${url}?host=database.example.com&password=private-fixture-sentinel`,
      '',
    ])(`rejects unsafe ${name} overrides before a driver connects: case %#`, (value) => {
      expect(() => assertFixtureDatabaseEnvironment({ [name]: value })).toThrow(`${name} overrides are disabled`);
      try { assertFixtureDatabaseEnvironment({ [name]: value }); }
      catch (error) { expect(String(error)).not.toContain(value || 'private-fixture-sentinel'); }
    });
  }

  it('ignores application database and credential settings', () => {
    expect(() => assertFixtureDatabaseEnvironment({
      DATABASE_URL: 'postgresql://example:dummy@database.example.com/production',
      PGHOST: 'database.example.com', PGUSER: 'example', PGPASSWORD: 'dummy', DATA_DIR: '/not-a-test-store',
    })).not.toThrow();
    expect(FIXTURE_DATABASE_URLS.PG_TEST_URL).toBe('postgresql://mcptest:mcptest@127.0.0.1:55432/shop');
  });
});
