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

async function proveSinglePP(logger: typeof log, pp: PerProgram) {
  const proofs = [];
  const ppId = identifyPerProgram(pp);

  const program = ZkProgram({
    name: ppId,
    publicOutput: Out,
    methods: pp.methods,
  });

  logger.start(`compiling ${ppId}`);
  await program.compile();
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
  return proofs;
}

export async function proveStep(
  logger: typeof log,
  step: Step,
  folder: string,
  stepIndex: number,
) {
  const pps = stepHandler(step);
  for (let pp of pps) {
    const ppId = identifyPerProgram(pp);
    const proofsOfPP = await proveSinglePP(logger, pp);
    for (let i = 0; i < proofsOfPP.length; i++) {
      const proofJsonName = `s_${stepIndex}_pp_${ppId}_i_${i}.json`;
      const proofJsonPath = path.join(folder, proofJsonName);
      await Bun.file(proofJsonPath).write(
        JSON.stringify(proofsOfPP[i].toJSON()),
      );
      logger.info("written", proofJsonName);
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
