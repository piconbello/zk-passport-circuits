import { DynamicProof, FeatureFlags, Field, Poseidon, Proof, SelfProof, Struct, VerificationKey, ZkProgram } from "o1js";
import { mytime } from "../../src/mytimer";

export class DynamicLeafProof extends DynamicProof<Field, Field> {
  static publicInputType = Field;
  static publicOutputType = Field;
  static maxProofsVerified = 0 as const;
  static featureFlags = {...FeatureFlags.allNone, xor: true};
}

export const selfMerger = ZkProgram({
  name: 'self-merger', // need a better name :)
  publicInput: Field, // vk hash
  publicOutput: Field,
  methods: {
    merge: {
      privateInputs: [SelfProof],//, DynamicLeafProof, VerificationKey],
      async method(vkHash: Field, selfProof: SelfProof<Field,Field>, nextProof: DynamicLeafProof, vk: VerificationKey) {
        // selfProof.verifyIf(selfProof.publicOutput.equals(Field(0)).not());
        // vkHash.assertEquals(selfProof.publicInput);
        // vkHash.assertEquals(Poseidon.hashPacked(VerificationKey, vk));
        // nextProof.verify(vk);
        // selfProof.publicOutput.assertEquals(nextProof.publicInput);
        return {
          publicOutput: Field(0),//nextProof.publicOutput
        };
      }
    }
  }
})

const proofsEnabled = true;

const { verificationKey } = await mytime(
  `Compiling self-merger zkProgram`,
  async () => selfMerger.compile({ proofsEnabled })
);
const { merge } = await selfMerger.analyzeMethods();
console.log(JSON.stringify(merge.summary()));

export const buildMerger = (verificationKey: VerificationKey) => 
  async (proofs: Proof<Field, Field>[]) => {
    const vkHash = Poseidon.hashPacked(VerificationKey, verificationKey)
    let proof = await selfMerger.Proof.dummy(vkHash, Field.from(0n), 2);
    // for (let i = 0; i < proofs.length; i++) {
    //   const res = await selfMerger.merge(
    //     vkHash,
    //     proof,
    //     DynamicLeafProof.fromProof(proofs[i]),
    //     verificationKey
    //   );
    //   proof = res.proof;
    // }
    return proof;
  }

export { verificationKey };