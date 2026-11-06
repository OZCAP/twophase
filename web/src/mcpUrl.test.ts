import { describe, expect, it } from 'vitest';
import { mcpOrigin, type ProxyStatus } from './api';

const status = (port: number | null) => ({ mcp: { port } }) as ProxyStatus;
const page = 'https://twophase.example.ts.net';

describe('mcpOrigin', () => {
  it("uses the page's origin when MCP shares it", () => {
    expect(mcpOrigin(null, page)).toBe(page);
    expect(mcpOrigin(status(null), page)).toBe(page);
    expect(mcpOrigin({} as ProxyStatus, page)).toBe(page); // older servers send no `mcp`
  });

  it("swaps in MCP's own port", () => {
    expect(mcpOrigin(status(8443), page)).toBe('https://twophase.example.ts.net:8443');
    expect(mcpOrigin(status(9001), 'https://twophase.example.ts.net:10000')).toBe('https://twophase.example.ts.net:9001');
    expect(mcpOrigin(status(8788), 'http://127.0.0.1:8787')).toBe('http://127.0.0.1:8788');
  });

  it("leaves out the scheme's default port", () => {
    expect(mcpOrigin(status(443), 'https://twophase.example.ts.net:8443')).toBe('https://twophase.example.ts.net');
  });
});
