import type { PerProgram } from "../unrolled_meta/interface";
import { expect } from "bun:test";
import { Out } from "../unrolled_meta/out";
import { Field, ZkProgram, VerificationKey } from "o1js";

export async function processPipeline(pps: PerProgram[]): Promise<Out> {
  let firstOutLeft: Field | null = null;
  let lastOutRight: Field | null = null;
  let previousOut: Out | null = null;
  let lastVerificationKey: VerificationKey | null = null;

  for (let i = 0; i < pps.length; i++) {
    const pp = pps[i];
    const programName = `PipelineProgram_${i}`;

    const Program = ZkProgram({
      name: programName,
      publicOutput: Out,
      methods: pp.methods,
    });

    let compileResult;
    try {
      console.log("Compiling", programName);
      compileResult = await Program.compile();
    } catch (compileError) {
      console.error(`Failed to compile ${programName}:`, compileError);
      throw compileError;
    }
    const { verificationKey } = compileResult;
    lastVerificationKey = verificationKey;

    for (const call of pp.calls) {
      const compiledMethod = Program[call.methodName];

      if (!compiledMethod) {
        throw new Error(
          `Method ${call.methodName} not found in compiled program ${programName}`,
        );
      }

      let proof;
      let currentOut: Out;
      try {
        console.log("Proving", programName, call.methodName);
        // @ts-ignore Ignore dynamic call signature issues
        proof = await compiledMethod(...call.args);
        currentOut = proof.proof.publicOutput as Out;
      } catch (error) {
        console.error(
          `Error proving call ${programName}.${call.methodName}:`,
          error,
        );
        console.error("Args passed:", call.args);
        throw new Error(
          `Error processing call ${programName}.${call.methodName}: ${error}`,
        );
      }

      if (firstOutLeft === null) {
        firstOutLeft = currentOut.left;
      }
      lastOutRight = currentOut.right; // Always update last known right

      if (previousOut !== null) {
        try {
          expect(
            previousOut.right.equals(currentOut.left).toBoolean(),
          ).toBeTrue();
          console.log("checked");
        } catch (error) {
          console.error("right is", programName, call.methodName);
          console.error(
            `Output linkage check FAILED between previous output R=${previousOut.right.toBigInt()} (VK Digest: ${previousOut.vkDigest.toString()}) and current output L=${currentOut.left.toBigInt()} (VK Digest: ${currentOut.vkDigest.toString()})`,
          );
          console.error(
            `Failure occurred processing call ${programName}.${call.methodName}`,
          );
          throw error;
        }
      }

      previousOut = currentOut; // Update previousOut for the next iteration's check
    }
  }

  if (firstOutLeft === null || lastOutRight === null) {
    console.warn(
      "Pipeline processing finished, but no proofs were generated. Returning default Out.",
    );
    return new Out({
      left: Field(0),
      right: Field(0),
      vkDigest: Field(0),
    });
  }

  const finalVkDigest = lastVerificationKey
    ? lastVerificationKey.hash
    : Field(0);

  return new Out({
    left: firstOutLeft,
    right: lastOutRight,
    vkDigest: finalVkDigest,
  });
}
