export type HealthBody = {
  ok: boolean;
  db: boolean | null;
  version: string;
  auth?: "ok" | "misconfigured";
  problems?: string[];
};
export type HealthResult = { status: 200 | 503; body: HealthBody };

export type HealthDeps = {
  /** Resolves when the database answers; null when no database is configured. */
  pingDb: (() => Promise<void>) | null;
  version: string;
  timeoutMs?: number;
  /** When true, a missing database counts as unhealthy (deployed environments). */
  requireDb?: boolean;
  /** Auth config reason codes; omitted means auth is not checked. */
  authProblems?: readonly string[];
};

async function checkDb({ pingDb, timeoutMs = 2000, requireDb = false }: HealthDeps): Promise<{ healthy: boolean; db: boolean | null }> {
  if (!pingDb) return { healthy: !requireDb, db: null };

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("timeout")), timeoutMs);
  });

  try {
    await Promise.race([pingDb(), timeout]);
    return { healthy: true, db: true };
  } catch {
    return { healthy: false, db: false };
  } finally {
    clearTimeout(timer);
  }
}

export async function getHealth(deps: HealthDeps): Promise<HealthResult> {
  const { healthy, db } = await checkDb(deps);
  const body: HealthBody = { ok: healthy, db, version: deps.version };

  if (deps.authProblems) {
    const authOk = deps.authProblems.length === 0;
    body.auth = authOk ? "ok" : "misconfigured";
    if (!authOk) {
      body.ok = false;
      body.problems = [...deps.authProblems];
    }
  }

  return { status: body.ok ? 200 : 503, body };
}
