import fs from "node:fs";

import { type Bundle, parseBundle } from "../src/parseBundle.ts";
import { ProofCache } from "../src/proofCache";
import * as pipeline from "../src/pipeline";
import * as merger from "../circuits/bimodal/merger";
import { time } from "../src/timer.ts";
import { DynamicProof, type ZkProgram } from "o1js";
import { DigestDG1 } from "../circuits/bimodal/digestDG1.ts";
import { DigestLDS } from "../circuits/bimodal/digestLDS.ts";

async function main() {
  const cache = new ProofCache();

  const file = fs.readFileSync("files/bundle.frodo.256-256-r1.json", "utf-8");
  const bundle = parseBundle(file);

  const { proof: proofDG1, vk: vkDG1 } = await pipeline.getLeafDG1(
    cache,
    bundle.dg1,
  );

  const { proof: proofLDS, vk: vkLDS } = await pipeline.getLeafLDS(
    cache,
    bundle.dg1,
    bundle.lds,
  );

  const { proof: proofSA, vk: vkSA } = await pipeline.getLeafSignedAttrs(
    cache,
    bundle.lds,
    bundle.signed_attrs,
  );

  // await time("Compiling Merger", async () => {
  //   // await DigestDG1.compile();
  //   // await DigestLDS.compile();
  //   // await merger.Merger.compile();
  // });

  await DigestLDS.compile();
  console.log("bef verify");
  proofLDS.verify();
  console.log("after verify");
  // const dyn = DynamicProof.fromProof(proofLDS);
  // const pr = await merger.Merger.processSingleLeaf(dyn, vkLDS);
  // console.log("HERE");
  return;

  // @ts-ignore
  const mergedProof: merger.MergerProof = await time(
    "Merging leaf proofs",
    async () => {
      return await merger.generateRootProof(
        // [proofDG1, proofLDS, proofSA],
        [proofLDS],
        // [vkDG1, vkLDS, vkSA],
        [vkLDS],
      );
    },
  );

  // sleep 0.5 sec
  await new Promise((resolve) => setTimeout(resolve, 500));

  const expectedVkDigest = merger.calculateRootVKDigest([vkLDS]);
  console.log(
    "Digests match:",
    expectedVkDigest.equals(mergedProof.publicOutput.vkDigest).toString(),
  );
}

await main();
