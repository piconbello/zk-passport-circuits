import { Field, Provable, Struct } from "o1js";
import { DynamicArray } from "@egemengol/mina-credentials";
import { MerkleTree, MerkleWitnessStep } from "../unrolled_meta/merkle";
import { Out } from "../unrolled_meta/out";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";

export function generateCall(
  pubkeyDigest: Field,
  merkleTree: MerkleTree,
  maxMerkleDepth: number,
): PerProgram {
  class Path extends DynamicArray(MerkleWitnessStep, {
    maxLength: maxMerkleDepth,
  }) {}
  class MasterlistContainsInput extends Struct({
    pubkeyDigest: Field,
    path: Path,
  }) {}

  const methods: ZkProgramMethods = {
    contains: {
      privateInputs: [MasterlistContainsInput],
      async method(inp: MasterlistContainsInput) {
        let merkleNode = inp.pubkeyDigest;
        inp.path.forEach((step, isDummy, _i) => {
          merkleNode = Provable.if(
            isDummy,
            merkleNode,
            step.calculateParentFor(merkleNode),
          );
        });
        return {
          publicOutput: new Out({
            left: inp.pubkeyDigest,
            right: merkleNode,
            vkDigest: Field(0),
          }),
        };
      },
    },
  };

  const witnessSteps = merkleTree.getWitnessOf(pubkeyDigest);

  const contains: PerProgram = {
    id: "Masterlist_Contains",
    methods: methods,
    calls: [
      {
        methodName: "contains",
        args: [
          new MasterlistContainsInput({
            pubkeyDigest: pubkeyDigest,
            path: Path.from(
              witnessSteps.map((s) => MerkleWitnessStep.fromStep(s)),
            ),
          }),
        ],
      },
    ],
  };
  return contains;
}
