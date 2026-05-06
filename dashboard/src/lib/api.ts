/**
 * Squash dashboard API client.
 *
 *   import.meta.env.VITE_SQUASH_API ??= ""
 *
 * - In development, vite proxies /api → http://localhost:8002 (see vite.config.ts).
 * - In production builds, set VITE_SQUASH_API to the full origin (e.g. https://api.getsquash.dev).
 * - When the server is unreachable, the dashboard automatically falls back to mocks.
 *
 * Every function returns a `{ ok, data, error }` discriminated result so the UI
 * can render fallbacks without throwing.
 */
import type { ScanResult } from "./types";
import { MOCK_SCAN_RESULT } from "./mock";

const BASE = (import.meta.env.VITE_SQUASH_API as string | undefined) ?? "";

export type ApiResult<T> =
  | { ok: true;  data: T;       fromMock?: boolean }
  | { ok: false; error: string; fromMock?: boolean };

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

/**
 * Run a side-by-side scan. Backed by /api/ollama-scan; falls back to mock
 * fixtures when the server is unreachable or Ollama isn't installed.
 */
export async function ollamaScan(seed?: number): Promise<ApiResult<ScanResult>> {
  try {
    const data = await postJson<ScanResult>("/api/ollama-scan", seed != null ? { seed } : {});
    if (!data.ok) {
      return { ok: true, data: MOCK_SCAN_RESULT, fromMock: true };
    }
    return { ok: true, data, fromMock: !data.available };
  } catch (e) {
    return { ok: true, data: MOCK_SCAN_RESULT, fromMock: true };
  }
}

export interface HealthResponse {
  ok: boolean;
  version?: string;
  tests?: number;
  served_at?: string;
}

export async function health(): Promise<ApiResult<HealthResponse>> {
  try {
    const res = await fetch(BASE + "/api/health");
    if (!res.ok) throw new Error(`${res.status}`);
    const data = (await res.json()) as HealthResponse;
    return { ok: true, data };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e), fromMock: true };
  }
}
