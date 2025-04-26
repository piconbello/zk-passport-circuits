import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { Out } from "../unrolled_meta/out";
import Contains from "../unrolled_meta/contains";
import { State as ContainsState } from "../unrolled_meta/contains";
import { DynamicBytes } from "@egemengol/mina-credentials";
import { Certificate } from "./constants"; // Assuming Certificate is defined here or adjust import
import type {
  PerProgram,
  ZkProgramMethods,
  Call,
} from "../unrolled_meta/interface";
import { DigestState_256 } from "./digest_256";

// Define DynamicBytes types for chunks and needle
// Adjust maxLength as needed for your specific certificate/pubkey constraints
export class PubkeyInCertChunk extends DynamicBytes({ maxLength: 600 }) {}
export class PubkeyInCertNeedle extends DynamicBytes({ maxLength: 600 }) {} // MaxLength should accommodate largest possible pubkey

// --- Method Definitions Object ---

export const PubkeyInCert_Methods: ZkProgramMethods = {
  processNonOverlappingChunk: {
    privateInputs: [Field, ContainsState, PubkeyInCertChunk],
    async method(
      pubkeyDigest: Field,
      leftState: ContainsState,
      chunk: PubkeyInCertChunk,
    ) {
      // Calculate the next state based on the current state and the chunk
      const rightState = Contains.processRegularChunk(leftState, chunk);
      // Return the output linking the previous state hash and the new state hash
      return {
        publicOutput: new Out({
          left: Poseidon.hash([pubkeyDigest, ...leftState.toFields()]),
          right: Poseidon.hash([pubkeyDigest, ...rightState.toFields()]),
          vkDigest: Field(0), // Placeholder for VK digest if needed later
        }),
      };
    },
  },
  processOverlappingChunk: {
    privateInputs: [
      Field,
      ContainsState,
      PubkeyInCertChunk,
      PubkeyInCertNeedle,
    ],
    async method(
      pubkeyDigest: Field,
      leftState: ContainsState,
      chunk: PubkeyInCertChunk,
      needle: PubkeyInCertNeedle,
    ) {
      // Calculate the next state, verifying the needle is present in this chunk
      const rightState = Contains.processOverlappingChunkDynamic(
        leftState,
        chunk,
        needle,
      );
      // Return the output linking the previous state hash and the new state hash
      return {
        publicOutput: new Out({
          left: Poseidon.hash([pubkeyDigest, ...leftState.toFields()]),
          right: Poseidon.hash([pubkeyDigest, ...rightState.toFields()]),
          vkDigest: Field(0), // Placeholder
        }),
      };
    },
  },
  validateContains_256: {
    privateInputs: [Field, ContainsState, Certificate], // Use the appropriate Certificate type
    async method(
      pubkeyDigest: Field,
      finalState: ContainsState,
      cert: Certificate,
    ) {
      // Assert that the needle (pubkey) was found during processing
      finalState.processedNeedle.assertTrue(
        "Public key needle must have been processed",
      );
      // Calculate the final digest of the entire certificate using the Contains.digest logic
      // Note: This assumes Contains.digest works correctly with the Certificate type
      const certDigest = Contains.digest(Poseidon.initialState(), cert)[0];

      const digestState = DigestState_256.initWithCarry(certDigest);

      // Return the output linking the final state hash and the certificate digest
      return {
        publicOutput: new Out({
          left: Poseidon.hash([pubkeyDigest, ...finalState.toFields()]),
          right: digestState.hashPoseidon(),
          vkDigest: Field(0), // Placeholder
        }),
      };
    },
  },
  // ident: {
  //   // Identity function, useful for padding or initial/final steps if needed
  //   privateInputs: [Field],
  //   async method(f: Field) {
  //     return {
  //       publicOutput: new Out({
  //         left: f,
  //         right: f,
  //         vkDigest: Field(0),
  //       }),
  //     };
  //   },
  // },
};

/**
 * Simulates the steps and generates the arguments for each ZkProgram call
 * required to prove that a public key exists within a certificate.
 *
 * @param cert - The certificate data as a Uint8Array.
 * @param pubkey - The public key data as a Uint8Array.
 * @returns An array containing one PerProgram object describing the sequence of calls.
 */
export function generateCall(cert: Uint8Array, pubkey: Uint8Array): PerProgram {
  // 1. Chunkify the haystack (certificate) based on the needle (pubkey)
  const { headingChunks, overlappingChunk, tailingChunks } =
    Contains.chunkifyHaystack(PubkeyInCertChunk.maxLength, cert, pubkey);

  // 2. Pre-calculate the public key digest (used as a constant carry value)
  // Ensure Bytes.from works correctly or use appropriate conversion
  const pubkeyBytes = Bytes.from(pubkey); // Use a consistent Bytes class if available
  const pubkeyDigest = Poseidon.hash(pubkeyBytes.bytes.map((u8) => u8.value));

  // 3. Initialize the state for the Contains logic
  let currentState: ContainsState = Contains.init();

  // 4. Prepare the list of calls
  const calls: Call[] = [];

  // 5. Simulate processing non-overlapping heading chunks
  for (const chunk of headingChunks) {
    const chunkBytes = PubkeyInCertChunk.fromBytes(chunk);
    const stateBefore = currentState; // Capture state *before* processing
    calls.push({
      methodName: "processNonOverlappingChunk",
      args: [pubkeyDigest, stateBefore, chunkBytes],
    });
    // Update state *outside* the ZkProgram for the next iteration's input
    currentState = Contains.processRegularChunk(stateBefore, chunkBytes);
  }

  // 6. Simulate processing the overlapping chunk
  const overlappingChunkBytes = PubkeyInCertChunk.fromBytes(overlappingChunk);
  const needleBytes = PubkeyInCertNeedle.fromBytes(pubkey);
  const stateBeforeOverlap = currentState; // Capture state *before* processing
  calls.push({
    methodName: "processOverlappingChunk",
    args: [
      pubkeyDigest,
      stateBeforeOverlap,
      overlappingChunkBytes,
      needleBytes,
    ],
  });
  // Update state *outside* the ZkProgram
  currentState = Contains.processOverlappingChunkDynamic(
    stateBeforeOverlap,
    overlappingChunkBytes,
    needleBytes,
  );

  // 7. Simulate processing non-overlapping tailing chunks
  for (const chunk of tailingChunks) {
    const chunkBytes = PubkeyInCertChunk.fromBytes(chunk);
    const stateBefore = currentState; // Capture state *before* processing
    calls.push({
      methodName: "processNonOverlappingChunk",
      args: [pubkeyDigest, stateBefore, chunkBytes],
    });
    // Update state *outside* the ZkProgram
    currentState = Contains.processRegularChunk(stateBefore, chunkBytes);
  }

  // 8. Simulate the final validation step
  const fullCertBytes = Certificate.fromBytes(cert); // Use the correct Certificate type
  const finalState = currentState; // Capture the final state
  calls.push({
    methodName: "validateContains_256",
    args: [pubkeyDigest, finalState, fullCertBytes],
  });

  // 9. Package the calls into the PerProgram structure
  const programDefinition: PerProgram = {
    methods: PubkeyInCert_Methods, // Reference the methods object
    calls: calls, // Provide the generated call sequence
  };

  return programDefinition;
}
