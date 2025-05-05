import { stepHandler } from "./handler";
import { type Step } from "./workerSchema";
import {
  identifyPerProgram,
  type PerProgram,
} from "../../unrolled_meta/interface";
import { Out } from "../../unrolled_meta/out";
import { ZkProgram } from "o1js";
import { log } from "../../unrolled_meta/logger";
import * as path from "node:path";
import { serializeRichProof, type RichProof } from "./richProof";
import { MergerProof } from "../../circuits/bimodal/merger";

async function proveSinglePP(logger: typeof log, pp: PerProgram) {
  const proofs = [];
  const ppId = identifyPerProgram(pp);

  const program = ZkProgram({
    name: ppId,
    publicOutput: Out,
    methods: pp.methods,
  });

  logger.start(`compiling ${ppId}`);
  const vk = (await program.compile()).verificationKey;
  logger.finish(`compiling ${ppId}`);

  for (const call of pp.calls) {
    const callable = program[call.methodName];
    try {
      logger.start(`proving ${ppId}.${call.methodName}`);
      // @ts-ignore
      const proof = (await callable(...call.args)).proof;
      logger.finish(`proving ${ppId}.${call.methodName}`);
      proofs.push(proof);
    } catch (error) {
      logger.error(
        "for perprogram",
        ppId,
        "method",
        call.methodName,
        "failed proving:",
        error,
      );
      throw new Error(
        `for perprogram ${ppId} method ${call.methodName} failed proving: ${error}`,
      );
    }
  }
  return { proofs, vk };
}

function proofFileName(iStep: number, iProof: number, ppId: string) {
  return `s_${iStep.toString().padStart(2, "0")}_${iProof.toString().padStart(2, "0")}_${ppId}.json`;
}

export async function proveStep(
  logger: typeof log,
  step: Step,
  folder: string,
  stepIndex: number,
) {
  const pps = stepHandler(step);
  let i = 0;
  for (let pp of pps) {
    const ppId = identifyPerProgram(pp);
    const { proofs: proofsOfPP, vk } = await proveSinglePP(logger, pp);
    for (let proof of proofsOfPP) {
      const proofJsonName = proofFileName(stepIndex, i, ppId);
      const proofJsonPath = path.join(folder, proofJsonName);
      const mergerProof = await MergerProof.fromJSON(proof.toJSON());
      const richProof: RichProof = {
        proof: mergerProof,
        vk,
      };
      const serialized = serializeRichProof(richProof);
      await Bun.file(proofJsonPath).write(serialized);
      logger.info("written", proofJsonName);
      i++;
    }
  }
}

process.on(
  "message",
  async ({
    step,
    folder,
    stepIndex,
  }: {
    step: Step;
    folder: string;
    stepIndex: number;
  }) => {
    const logger = log.scope(step.step);
    try {
      await proveStep(logger, step, folder, stepIndex);

      // Signal completion and exit
      if (process.send) {
        process.send("done");
      }
      process.exit(0); // Explicitly exit the process
    } catch (error) {
      logger.error("Error in worker:", error);
      process.exit(1);
    }
  },
);
