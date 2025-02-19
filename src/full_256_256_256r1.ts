import { type Bundle, parseBundle } from "./parseBundle.ts";
import * as Full from "../circuits/full_256_256_256r1.ts";
// import { time } from "./timer";
import fs from "node:fs";

async function process(bundle: Bundle) {
  await Full.Full_256_256_256r1.compile();
  // await time("compile", async () => await Full.Full_256_256_256r1.compile());
}

async function main() {
  const file = fs.readFileSync("files/bundle.frodo.256-256-r1.json", "utf-8");
  const bundle = parseBundle(file);

  await process(bundle);
}
await main();
