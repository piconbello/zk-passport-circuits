import { stepHandler } from "./handler";
import { prepareStepInputsForExpiredBundle } from "./realExpired";
import { StepSchema, type Step } from "./workerSchema";
import {
  identifyPerProgram,
  type PerProgram,
} from "../../unrolled_meta/interface";
import { expect } from "bun:test";
import { Out } from "../../unrolled_meta/out";
import { Field, ZkProgram } from "o1js";
import { log } from "../../unrolled_meta/logger";
import * as path from "node:path";
import { parseArgs } from "node:util";
import * as fs from "node:fs";

// async function proveSinglePP(pp: PerProgram) {
//   const proofs = [];
//   const ppId = identifyPerProgram(pp);

//   const program = ZkProgram({
//     name: ppId,
//     publicOutput: Out,
//     methods: pp.methods,
//   });

//   log.start(`compiling ${ppId}`);
//   await program.compile();
//   log.finish(`compiling ${ppId}`);

//   for (const call of pp.calls) {
//     const callable = program[call.methodName];
//     try {
//       log.start(`proving ${ppId}.${call.methodName}`);
//       // @ts-ignore
//       const proof = (await callable(...call.args)).proof;
//       log.finish(`proving ${ppId}.${call.methodName}`);
//       proofs.push(proof);
//     } catch (error) {
//       log.error(
//         "for perprogram",
//         ppId,
//         "method",
//         call.methodName,
//         "failed proving:",
//         error,
//       );
//       throw new Error(
//         `for perprogram ${ppId} method ${call.methodName} failed proving: ${error}`,
//       );
//     }
//   }
//   return proofs;
// }

// export async function proveStep(step: Step, folder: string, stepIndex: number) {
//   const pps = stepHandler(step);
//   for (let pp of pps) {
//     const ppId = identifyPerProgram(pp);
//     const proofsOfPP = await proveSinglePP(pp);
//     for (let i = 0; i < proofsOfPP.length; i++) {
//       const proofJsonName = `s_${stepIndex}_pp_${ppId}_i_${i}.json`;
//       const proofJsonPath = path.join(folder, proofJsonName);
//       await Bun.file(proofJsonPath).write(
//         JSON.stringify(proofsOfPP[i].toJSON()),
//       );
//       log.info("written", proofJsonName);
//     }
//   }
// }

async function processStep(folder: string, i: number) {}

async function prepareSteps(folder: string) {
  const files = fs.readdirSync(folder);
  for (const file of files) {
    if (file.endsWith(".json")) {
      const filePath = path.join(folder, file);
      fs.unlinkSync(filePath);
      log.info("removed:", file);
    }
  }
  const stepsB64 = await prepareStepInputsForExpiredBundle();
  // @ts-ignore
  const stepsJson = path.join(folder, "steps.json");
  await Bun.file(stepsJson).write(JSON.stringify(stepsB64));
  log.info("written: steps.json");
}

async function main() {
  const { positionals } = parseArgs({
    args: Bun.argv,
    strict: true,
    allowPositionals: true,
  });
  const folder = positionals[2];
  if (folder === undefined) {
    throw new Error("Require worker folder as the first argument");
  }
  const files = fs.readdirSync(folder);
  for (const file of files) {
    if (file.endsWith(".json")) {
      const filePath = path.join(folder, file);
      fs.unlinkSync(filePath);
      log.info("removed:", file);
    }
  }
  const stepsB64 = await prepareStepInputsForExpiredBundle();
  for (let i = 0; i < stepsB64.length; i++) {
    const step = StepSchema.parse(stepsB64[i]);
    log.start("spawning child for step", step.step);
    const childProc = Bun.spawn(["bun", "pipelines/registry/proverWorker.ts"], {
      stdio: ["inherit", "inherit", "inherit"],
      ipc() {
        // log.info(`${step.step} responded`);
      },
    });
    childProc.send({ step, folder, stepIndex: i });
    await childProc.exited;
    if (childProc.exitCode !== 0) {
      log.error("child failed");
      return;
    }
    log.finish("spawning child for step", step.step);
  }
}

if (import.meta.path === Bun.main) {
  await main();
}

// export async function prove(pps: PerProgram[]) {
//   const outs: Out[] = [];
//   let i = 0;
//   for (const pp of pps) {
//     console.log("pp", Object.keys(pp.methods));
//     for (const call of pp.calls) {
//       console.log(i, "methodName", call.methodName);
//       const callable = pp.methods[call.methodName];
//       // console.log(call.methodName, callable);
//       try {
//         const proof = await callable.method(...call.args);
//         // console.log("lefttt", proof.publicOutput.left.toBigInt());
//         outs.push(proof.publicOutput);
//       } catch (error) {
//         console.error(pp);
//         throw new Error(`Error processing call ${call.methodName}: ${error}`);
//       }
//       i++;
//     }
//   }
//   for (let i = 0; i < outs.length; i++) {
//     console.log("out", i);
//     console.log("out left", outs[i].left.toBigInt());
//     console.log("out right", outs[i].right.toBigInt());
//   }
//   for (let i = 0; i < outs.length - 1; i++) {
//     try {
//       expect(outs[i].right.equals(outs[i + 1].left).toBoolean()).toBeTrue();
//     } catch (error) {
//       console.log("left.i", i);
//       console.log("left.right", outs[i].right.toBigInt());
//       console.log("right.left", outs[i + 1].left.toBigInt());
//       // console.log("left i", i);
//       // console.error("left", Object.keys(pps[i].methods));
//       // console.error(outs[i].right.toBigInt());
//       // console.log(i + 1);
//       // console.error("right", Object.keys(pps[i + 1].methods));
//       // console.error(outs[i + 1].left.toBigInt());

//       throw error;
//     }
//   }
//   return {
//     left: outs[0].left,
//     right: outs[outs.length - 1].right,
//     vkDigest: Field(0), // temporary ofc
//   } as Out;
// }

// if (import.meta.path === Bun.main) {
//   // this script is being directly executed
// } else {
//   // this file is being imported from another script
// }

// async function main() {
//   const stepsB64 = await prepareStepInputsForExpiredBundle();
//   // @ts-ignore
//   const steps: Step[] = stepsB64.map(StepSchema.parse);
//   await proveStep(steps[0], "./files/worker", 0);
//   // const perPrograms = steps.flatMap(stepHandler);
//   // const proof = await proveSinglePP(perPrograms[0]);
//   // console.log("out.left!", proof[0].publicOutput.left.toBigInt());
// }

// main();
