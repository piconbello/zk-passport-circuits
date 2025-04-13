import type { PerProgram } from "../unrolled_meta/interface";
import { expect } from "bun:test";
import type { Out } from "../unrolled_meta/out";
import { Field } from "o1js";

export async function processFast(pps: PerProgram[]) {
  const outs: Out[] = [];
  for (const pp of pps) {
    for (const call of pp.calls) {
      const callable = pp.methods[call.methodName];
      try {
        const proof = await callable.method(...call.args);
        outs.push(proof.publicOutput);
      } catch (error) {
        console.error(pp);
        throw new Error(`Error processing call ${call.methodName}: ${error}`);
      }
    }
  }
  for (let i = 0; i < outs.length - 1; i++) {
    try {
      expect(outs[i].right.equals(outs[i + 1].left).toBoolean()).toBeTrue();
    } catch (error) {
      console.error("left", pps[i].methods);
      console.error(outs[i].right.toBigInt());
      console.error("right", pps[i + 1].methods);
      console.error(outs[i + 1].left.toBigInt());

      throw error;
    }
  }
  return {
    left: outs[0].left,
    right: outs[outs.length - 1].right,
    vkDigest: Field(0), // temporary ofc
  } as Out;
}
