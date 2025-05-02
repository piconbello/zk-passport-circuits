import { stepHandler } from "./handler";
import { prepareStepInputsForExpiredBundle } from "./realExpired";
import { StepSchema, type Step } from "./workerSchema";
import type { PerProgram } from "../../unrolled_meta/interface";
import { expect } from "bun:test";
import type { Out } from "../../unrolled_meta/out";
import { Field } from "o1js";

export async function processFast(pps: PerProgram[]) {
  const outs: Out[] = [];
  let i = 0;
  for (const pp of pps) {
    console.log("pp", Object.keys(pp.methods));
    for (const call of pp.calls) {
      console.log(i, "methodName", call.methodName);
      const callable = pp.methods[call.methodName];
      // console.log(call.methodName, callable);
      try {
        const proof = await callable.method(...call.args);
        // console.log("lefttt", proof.publicOutput.left.toBigInt());
        outs.push(proof.publicOutput);
      } catch (error) {
        console.error(pp);
        throw new Error(`Error processing call ${call.methodName}: ${error}`);
      }
      i++;
    }
  }
  for (let i = 0; i < outs.length; i++) {
    console.log("out", i);
    console.log("out left", outs[i].left.toBigInt());
    console.log("out right", outs[i].right.toBigInt());
  }
  for (let i = 0; i < outs.length - 1; i++) {
    try {
      expect(outs[i].right.equals(outs[i + 1].left).toBoolean()).toBeTrue();
    } catch (error) {
      console.log("left.i", i);
      console.log("left.right", outs[i].right.toBigInt());
      console.log("right.left", outs[i + 1].left.toBigInt());
      // console.log("left i", i);
      // console.error("left", Object.keys(pps[i].methods));
      // console.error(outs[i].right.toBigInt());
      // console.log(i + 1);
      // console.error("right", Object.keys(pps[i + 1].methods));
      // console.error(outs[i + 1].left.toBigInt());

      throw error;
    }
  }
  return {
    left: outs[0].left,
    right: outs[outs.length - 1].right,
    vkDigest: Field(0), // temporary ofc
  } as Out;
}

async function main() {
  const stepsB64 = await prepareStepInputsForExpiredBundle();
  // @ts-ignore
  const steps: Step[] = stepsB64.map(StepSchema.parse);
  const perPrograms = steps.flatMap(stepHandler);
  const out = await processFast(perPrograms);
  console.log("out!");
}

main();
