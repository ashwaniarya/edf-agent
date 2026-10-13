import { authSmokeCheck, smokeCheck } from "./smoke-check";

const base = process.argv[2] ?? process.env.BASE_URL;
if (!base) {
  console.error("usage: npm run smoke -- <base-url>");
  process.exit(2);
}

for (let attempt = 1; attempt <= 10; attempt++) {
  const health = await smokeCheck(base);
  const auth = health.pass ? await authSmokeCheck(base) : health;
  if (health.pass && auth.pass) {
    console.log(`smoke OK ${base} version=${health.version} mcp=${"resource" in auth ? auth.resource : "?"}`);
    process.exit(0);
  }
  console.log(`attempt ${attempt}: ${"reason" in auth ? auth.reason : "unknown"}`);
  await new Promise((s) => setTimeout(s, 6000));
}
console.error(`smoke FAILED ${base}`);
process.exit(1);
