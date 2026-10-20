import { describe, expect, it } from 'vitest';
import { parseConnectionString as parse, suggestName } from './connstr';

describe('parseConnectionString', () => {
  it.each([
    ['postgresql://app:s3cret@db.internal:5433/shop?sslmode=require', { engine: 'postgres', host: 'db.internal', port: 5433, database: 'shop', user: 'app', password: 's3cret', sslmode: 'require' }],
    // Supabase pooler: dotted user, percent-encoded password, no sslmode.
    ['postgres://postgres.abcd:p%40ss%2Fw0rd@aws-0-eu-west-1.pooler.supabase.com:6543/postgres', { user: 'postgres.abcd', password: 'p@ss/w0rd', port: 6543, database: 'postgres', sslmode: null }],
    // Neon: default port, extra parameters.
    ['postgresql://owner:npg_x@ep-cool-1.eu-central-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require', { port: 5432, database: 'neondb', sslmode: 'require' }],
    // libpq: database defaults to the user name.
    ['postgresql://me@localhost', { database: 'me', port: 5432, password: '' }],
    ['postgresql://u:p@[::1]:5432/db', { host: '::1' }],
    ['jdbc:postgresql://h:5432/db?sslmode=verify-full', { host: 'h', sslmode: 'verify-full' }],
    ['postgresql+psycopg2://u:p@h/db', { engine: 'postgres', database: 'db' }],
    ["host=db.internal port=5432 dbname=app user=me password='a b' sslmode=verify-ca", { host: 'db.internal', database: 'app', password: 'a b', sslmode: 'require' }],
    ['mysql://root:pw@127.0.0.1:3306/shop', { engine: 'mysql', port: 3306, database: 'shop' }],
    // PlanetScale.
    ['mysql://abc:pscale_pw_x@aws.connect.psdb.cloud/mydb?sslaccept=strict', { engine: 'mysql', sslmode: 'verify-full' }],
    ['mysql://u:p@h:3307/db?ssl-mode=REQUIRED', { sslmode: 'require', port: 3307 }],
    ['mysql://u:p@h/db?ssl={"rejectUnauthorized":true}', { sslmode: 'verify-full' }],
    ['mariadb://u:p@h/db', { engine: 'mariadb', port: 3306 }],
    ['mysql+pymysql://u:p@h/db?charset=utf8mb4', { engine: 'mysql', database: 'db' }],
  ])('%s', (input, expected) => {
    expect(parse(input, 'postgres')).toMatchObject(expected);
  });

  it('keeps MariaDB when the string says mysql://', () => {
    expect(parse('mysql://u:p@h/shop', 'mariadb').engine).toBe('mariadb');
  });

  it('notes what it could not carry over exactly', () => {
    expect(parse('postgresql://u:p@h/db?sslmode=verify-ca', 'postgres').notes[0]).toMatch(/verify-ca/);
    expect(parse('mysql://u:p@h', 'mysql').notes[0]).toMatch(/No database name/);
  });

  it.each([
    ['mongodb://u:p@h/db', /Unsupported scheme "mongodb/],
    ['just some text', /Not a connection string/],
    ['postgresql://u:p@h1:5432,h2:5432/db', /Multiple hosts/],
  ])('rejects %s', (input, message) => {
    expect(() => parse(input, 'postgres')).toThrow(message);
  });

  it('suggests a name', () => {
    expect(suggestName({ database: 'orders', host: 'x' })).toBe('Orders');
    expect(suggestName({ database: '', host: 'billing.internal' })).toBe('Billing');
  });
});
