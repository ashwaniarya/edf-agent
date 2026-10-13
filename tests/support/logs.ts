import { format } from "node:util";

type Spy = { mock: { calls: unknown[][] } };

/** What the spied console methods printed, formatted the way console does (JSON.stringify turns an Error into {}). */
export const logged = (...spies: Spy[]) => spies.flatMap((s) => s.mock.calls.map((args) => format(...args))).join("\n");

/** Secrets, internals and PII the tests seed into errors and tokens, plus stack traces (a raw Error was logged). */
export const LEAK = /hunter2|password=|ECONNREFUSED|10\.0\.0\.5|BETTER_AUTH_SECRET|user_[AB]\b|@example\.com|Jwks failed|malformed|\n\s+at /;
