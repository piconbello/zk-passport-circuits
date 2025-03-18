import path from "node:path";
import {
  Field,
  Bytes,
  Proof,
  VerificationKey,
  ZkProgram,
  Poseidon,
  Bool,
} from "o1js";
import {
  PubkeyInCert,
  PubkeyInCertCert,
  PubkeyInCertChunk,
  PubkeyInCertNeedle,
} from "../unrolled_leaves/pubkey_in_cert";
import { State as ContainsState } from "./contains";
import Contains from "./contains";
import { Out } from "./out";
import { ProofCache } from "../src/proofCache";
import { time } from "../src/timer.ts";
import { once } from "./utils.ts";
import { vkToJSON, vkFromJSON } from "./merger_utils";
import { DynamicBytes } from "@egemengol/mina-credentials";

// Compile PubkeyInCert program only once
const compilePubkeyInCert = once(async () => {
  return await time("Compiling PubkeyInCert program", async () => {
    return await PubkeyInCert.compile();
  });
});

/**
 * Generate a series of proofs to verify that a public key exists in a certificate
 *
 * @param pubkeyDigest - The hash of the public key to find
 * @param cert - The certificate data as a Uint8Array
 * @param pubkey - The actual public key to find as a Uint8Array
 * @param cache - The ProofCache instance to use
 * @returns An array of proofs and their verification key
 */
export async function generatePubkeyInCertProofs(
  cert: Uint8Array,
  pubkey: Uint8Array,
  cache: ProofCache,
): Promise<{
  proofs: Proof<undefined, Out>[];
  verificationKey: VerificationKey;
}> {
  const { headingChunks, overlappingChunk, tailingChunks } =
    Contains.chunkifyHaystack(PubkeyInCertChunk.maxLength, cert, pubkey);
  const pubkeyDigest = Poseidon.hash(
    Bytes.from(pubkey).bytes.map((u8) => u8.value),
  );

  // Initialize state
  let currentState = Contains.init();

  // Create all proof objects array
  const proofs = [];
  let verificationKey: VerificationKey | undefined = undefined;

  // Process heading chunks (before the pubkey)
  for (let i = 0; i < headingChunks.length; i++) {
    const chunk = headingChunks[i];
    const chunkBytes = PubkeyInCertChunk.fromBytes(chunk);

    // First compute the next state in local code
    currentState = Contains.processRegularChunk(currentState, chunkBytes);

    const chunkResult = await cache.getProof(
      path.resolve(__dirname, "../unrolled_leaves/pubkey_in_cert.ts"),
      `non_overlapping_${i}_${chunk.length}`,
      async () => {
        return await time(`Processing non-overlapping chunk ${i}`, async () => {
          // Compile the program here and get the verification key
          const compiled = await compilePubkeyInCert();

          // Use the previous state and chunk to generate the proof
          const proof = (
            await PubkeyInCert.processNonOverlappingChunk(
              pubkeyDigest,
              // We use the state before this chunk was processed
              proofs.length > 0
                ? Contains.processRegularChunk(
                    Contains.init(),
                    PubkeyInCertChunk.fromBytes(headingChunks[i - 1]),
                  )
                : Contains.init(),
              chunkBytes,
            )
          ).proof;

          return {
            proofJSON: JSON.stringify(proof.toJSON()),
            verificationKeyJSON: vkToJSON(compiled.verificationKey),
          };
        });
      },
    );

    // Get the verification key from the result if we don't have it yet
    if (!verificationKey) {
      verificationKey = vkFromJSON(chunkResult.verificationKeyJSON);
    }

    const proof = await ZkProgram.Proof(PubkeyInCert).fromJSON(
      JSON.parse(chunkResult.proofJSON),
    );

    proofs.push(proof);
  }

  // Process the overlapping chunk (containing the pubkey)
  const overlappingBytes = PubkeyInCertChunk.fromBytes(overlappingChunk);
  const needleBytes = PubkeyInCertNeedle.fromBytes(pubkey);

  // Compute new state after processing the overlapping chunk
  const stateBeforeOverlap = currentState;
  currentState = Contains.processOverlappingChunkDynamic(
    currentState,
    overlappingBytes,
    needleBytes,
  );

  const overlappingResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/pubkey_in_cert.ts"),
    `overlapping_${pubkey.length}`,
    async () => {
      return await time(
        "Processing overlapping chunk with pubkey",
        async () => {
          // Compile the program here and get the verification key
          const compiled = await compilePubkeyInCert();

          const proof = (
            await PubkeyInCert.processOverlappingChunk(
              pubkeyDigest,
              stateBeforeOverlap,
              overlappingBytes,
              needleBytes,
            )
          ).proof;

          return {
            proofJSON: JSON.stringify(proof.toJSON()),
            verificationKeyJSON: vkToJSON(compiled.verificationKey),
          };
        },
      );
    },
  );

  // Get the verification key from the result if we don't have it yet
  if (!verificationKey) {
    verificationKey = vkFromJSON(overlappingResult.verificationKeyJSON);
  }

  const overlappingProof = await ZkProgram.Proof(PubkeyInCert).fromJSON(
    JSON.parse(overlappingResult.proofJSON),
  );

  proofs.push(overlappingProof);

  // Process tailing chunks (after the pubkey)
  for (let i = 0; i < tailingChunks.length; i++) {
    const chunk = tailingChunks[i];
    const chunkBytes = PubkeyInCertChunk.fromBytes(chunk);

    // Store the state before processing
    const stateBeforeTailing = currentState;

    // Update the state by processing this chunk
    currentState = Contains.processRegularChunk(currentState, chunkBytes);

    const chunkResult = await cache.getProof(
      path.resolve(__dirname, "../unrolled_leaves/pubkey_in_cert.ts"),
      `tailing_${i}_${chunk.length}`,
      async () => {
        return await time(`Processing tailing chunk ${i}`, async () => {
          // Compile the program here and get the verification key
          const compiled = await compilePubkeyInCert();

          const proof = (
            await PubkeyInCert.processNonOverlappingChunk(
              pubkeyDigest,
              stateBeforeTailing,
              chunkBytes,
            )
          ).proof;

          return {
            proofJSON: JSON.stringify(proof.toJSON()),
            verificationKeyJSON: vkToJSON(compiled.verificationKey),
          };
        });
      },
    );

    // Get the verification key from the result if we don't have it yet
    if (!verificationKey) {
      verificationKey = vkFromJSON(chunkResult.verificationKeyJSON);
    }

    const tailingProof = await ZkProgram.Proof(PubkeyInCert).fromJSON(
      JSON.parse(chunkResult.proofJSON),
    );

    proofs.push(tailingProof);
  }

  // Final validation
  const finalResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/pubkey_in_cert.ts"),
    `validate_contains_${pubkey.length}`,
    async () => {
      return await time("Validating pubkey in cert", async () => {
        // Compile the program here and get the verification key
        const compiled = await compilePubkeyInCert();

        const certBytes = PubkeyInCertCert.fromBytes(cert);
        const proof = (
          await PubkeyInCert.validateContains(
            pubkeyDigest,
            currentState,
            certBytes,
          )
        ).proof;

        return {
          proofJSON: JSON.stringify(proof.toJSON()),
          verificationKeyJSON: vkToJSON(compiled.verificationKey),
        };
      });
    },
  );

  // Get the verification key from the result if we don't have it yet
  if (!verificationKey) {
    verificationKey = vkFromJSON(finalResult.verificationKeyJSON);
  }

  const finalProof = await ZkProgram.Proof(PubkeyInCert).fromJSON(
    JSON.parse(finalResult.proofJSON),
  );

  proofs.push(finalProof);

  // Return all proofs and the verification key
  return {
    proofs,
    verificationKey,
  };
}
