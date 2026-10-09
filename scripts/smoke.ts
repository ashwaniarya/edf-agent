import { smokeCheck } from "./smoke-check";

const base = process.argv[2] ?? process.env.BASE_URL;
if (!base) {
  console.error("usage: npm run smoke -- <base-url>");
  process.exit(2);
}

for (let attempt = 1; attempt <= 10; attempt++) {
  const r = await smokeCheck(base);
  if (r.pass) {
    console.log(`smoke OK ${base} version=${r.version}`);
    process.exit(0);
  }
  console.log(`attempt ${attempt}: ${r.reason}`);
  await new Promise((s) => setTimeout(s, 6000));
}
console.error(`smoke FAILED ${base}`);
process.exit(1);
