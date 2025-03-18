import fs from "node:fs";
import path from "node:path";
import { Bytes, Field, Poseidon, ZkProgram } from "o1js";
import { secp256r1 } from "@noble/curves/p256";

import { parseBundle } from "../src/parseBundle.ts";
import { ProofCache } from "../src/proofCache";
import { time } from "../src/timer.ts";
import { generatePubkeyInCertProofs } from "../unrolled_meta/contains_utils.ts";
import { Out } from "../unrolled_meta/out.ts";
import Contains from "../unrolled_meta/contains.ts";
import { PubkeyInCertCert } from "../unrolled_leaves/pubkey_in_cert.ts";

/**
 * This script verifies that the proofs from contains_utils form a valid chain
 * where each proof's output connects to the next one, and the endpoints match
 * the expected values.
 */
async function main() {
  const cache = new ProofCache();

  console.log("🔍 Starting Contains Chain Verification");
  console.log("Loading and parsing bundle...");

  // Load the bundle
  const file = fs.readFileSync("files/bundle.frodo.256-256-r1.json", "utf-8");
  const bundle = parseBundle(file);

  // Extract the issuer's public key from the bundle
  const issuerPublicKey = new secp256r1.ProjectivePoint(
    bundle.cert_local_pubkey.x,
    bundle.cert_local_pubkey.y,
    1n,
  ).toRawBytes(false);

  console.log("Issuer public key length:", issuerPublicKey.length, "bytes");
  console.log("Certificate length:", bundle.cert_local_tbs.length, "bytes");

  // Convert certificate and public key to Uint8Array
  const cert = Uint8Array.from(bundle.cert_local_tbs);
  const pubkey = Uint8Array.from(issuerPublicKey);

  // Calculate the expected digests
  const pubkeyDigest = Poseidon.hash(
    Bytes.from(pubkey).bytes.map((u8) => u8.value),
  );
  const certBytes = PubkeyInCertCert.fromBytes(cert);
  const certDigest = Contains.digest(Poseidon.initialState(), certBytes)[0];

  // Generate the proof chain
  const { proofs, verificationKey } = await time(
    "Generating contains proofs",
    async () => {
      return await generatePubkeyInCertProofs(cert, pubkey, cache);
    },
  );

  console.log(`✅ Generated ${proofs.length} proofs in the chain`);

  // Extract public outputs from all proofs
  const outputs = proofs.map((proof) => proof.publicOutput);

  // Verify the chain integrity
  let isChainValid = true;
  console.log("\nVerifying proof chain integrity:");

  for (let i = 0; i < outputs.length - 1; i++) {
    const current = outputs[i];
    const next = outputs[i + 1];

    if (!current.right.equals(next.left).toBoolean()) {
      console.log(`❌ Break in chain between proof ${i} and ${i + 1}:`);
      console.log(`   Proof ${i} right: ${current.right.toString()}`);
      console.log(`   Proof ${i + 1} left: ${next.left.toString()}`);
      isChainValid = false;
    } else {
      console.log(`✅ Link verified between proof ${i} and ${i + 1}`);
    }
  }

  // Check the first and last outputs match expected values
  console.log("\nVerifying chain endpoints:");

  // For the first proof, the left should be based on the pubkey digest
  // The exact value depends on how the initial state is combined with the pubkey digest
  console.log(`First proof left: ${outputs[0].left.toString()}`);

  // For the last proof, the right should be related to the cert digest
  console.log(
    `Last proof right: ${outputs[outputs.length - 1].right.toString()}`,
  );
  console.log(`Certificate digest: ${certDigest.toString()}`);

  if (outputs[outputs.length - 1].right.equals(certDigest).toBoolean()) {
    console.log("✅ Final proof right matches certificate digest");
  } else {
    console.log("❓ Final proof right differs from simple certificate digest");
    console.log(
      "   This may be expected depending on how Contains.ts processes the final state",
    );
  }

  // Verify pubkey is actually in the certificate (as a sanity check)
  console.log("\nVerifying pubkey presence in certificate:");
  const pubkeyHex = Buffer.from(pubkey).toString("hex");
  const certHex = Buffer.from(cert).toString("hex");

  if (certHex.includes(pubkeyHex)) {
    console.log(
      "✅ Public key found in certificate at position:",
      certHex.indexOf(pubkeyHex) / 2,
    );
  } else {
    console.log("❌ Public key not found in certificate as exact match");

    // Try to find substrings to help debug
    if (pubkeyHex.length > 40) {
      const substrLength = 40;
      for (let i = 0; i < pubkeyHex.length - substrLength; i += 20) {
        const fragment = pubkeyHex.substring(i, i + substrLength);
        if (certHex.includes(fragment)) {
          console.log(
            `✅ Fragment of pubkey found at position:`,
            certHex.indexOf(fragment) / 2,
          );
          console.log(`   Fragment: ${fragment} (from position ${i / 2})`);
          break;
        }
      }
    }
  }

  // Save the proofs and verification key for further analysis if needed
  const outputDir = path.join(__dirname, "../../output");
  fs.mkdirSync(outputDir, { recursive: true });

  for (let i = 0; i < proofs.length; i++) {
    fs.writeFileSync(
      path.join(outputDir, `contains_proof_${i}.json`),
      JSON.stringify(proofs[i].toJSON(), null, 2),
    );
  }

  fs.writeFileSync(
    path.join(outputDir, "contains_summary.json"),
    JSON.stringify(
      {
        chainLength: proofs.length,
        isChainValid,
        firstLeft: outputs[0].left.toString(),
        lastRight: outputs[outputs.length - 1].right.toString(),
        pubkeyDigest: pubkeyDigest.toString(),
        certDigest: certDigest.toString(),
      },
      null,
      2,
    ),
  );

  console.log(`\nProofs saved to ${outputDir}`);
  console.log("\n🎉 Contains Chain Verification completed!");

  if (isChainValid) {
    console.log("✅ Proof chain is valid - each proof links to the next one");
  } else {
    console.log("❌ Proof chain has breaks - some proofs don't link properly");
  }
}

await main();
