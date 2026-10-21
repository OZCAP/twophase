import { Api, ApiError, type AuthInfo } from './api';

export type AuthGate =
  | { state: 'checking' }
  | { state: 'ready'; token: string; info: AuthInfo }
  | { state: 'login'; info: AuthInfo }
  | { state: 'blocked'; message: string };

/** Password sessions live in HttpOnly cookies; only legacy admin tokens are browser-managed. */
export async function detectAuth(savedToken: string | null): Promise<AuthGate> {
  try {
    const info = await new Api('').auth();
    const token = info.mode === 'token' ? savedToken ?? '' : '';
    try {
      await new Api(token).status();
      return { state: 'ready', token, info };
    } catch (error) {
      if (error instanceof ApiError && error.status === 401 && error.code !== 'tailscale_required') return { state: 'login', info };
      throw error;
    }
  } catch (error) {
    return { state: 'blocked', message: error instanceof Error ? error.message : 'Unable to connect to the proxy' };
  }
}
