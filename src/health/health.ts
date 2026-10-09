export type HealthBody = { ok: boolean; db: boolean | null; version: string };
export type HealthResult = { status: 200 | 503; body: HealthBody };

export type HealthDeps = {
  /** Resolves when the database answers; null when no database is configured. */
  pingDb: (() => Promise<void>) | null;
  version: string;
  timeoutMs?: number;
  /** When true, a missing database counts as unhealthy (deployed environments). */
  requireDb?: boolean;
};

export async function getHealth({ pingDb, version, timeoutMs = 2000, requireDb = false }: HealthDeps): Promise<HealthResult> {
  if (!pingDb) {
    return requireDb
      ? { status: 503, body: { ok: false, db: null, version } }
      : { status: 200, body: { ok: true, db: null, version } };
  }

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
  });

  try {
    await Promise.race([pingDb(), timeout]);
    return { status: 200, body: { ok: true, db: true, version } };
  } catch {
    return { status: 503, body: { ok: false, db: false, version } };
  } finally {
    clearTimeout(timer);
  }
}
