// TODO IMPLEMENT SAME BEHAVIOR AS runPostMerge.ts but using Experimental Recursive API.
import { Field, ZkProgram, Experimental, FeatureFlags, DynamicProof, Proof, SelfProof, Undefined, verify } from 'o1js';
import { mytime } from '../src/mytimer';

// class DynLeafProof extends DynamicProof<Field, Field> {
//   static publicInputType = Field;
//   static publicOutputType = Field;
//   static maxProofsVerified = 2 as const;

//   static featureFlags = FeatureFlags.allMaybe;
// }

export const leafProgZero = ZkProgram({
  name: 'leaf-prog-zero',
  publicInput: Field,
  publicOutput: Field,
  methods: {
    initLeaf: {
      privateInputs: [],
      async method(publicInput: Field) {
        return { publicOutput: publicInput.mul(Field(2)) };
      }
    }
  }
});
export let leafProgZeroRec = Experimental.Recursive(leafProgZero);

export const leafProgOne = ZkProgram({
  name: 'leaf-prog-one',
  publicInput: Field,
  publicOutput: Field,
  methods: {
    initLeaf: {
      privateInputs: [],
      async method(publicInput: Field) {
        return { publicOutput: publicInput.mul(Field(2)) };
      }
    },
    mergeOne: {
      privateInputs: [],
      async method(publicInput: Field) {
        let x: Field = await leafProgOneRec.initLeaf(publicInput);
        return { publicOutput: x.mul(3) };
      }
    }
  }
})
export let leafProgOneRec = Experimental.Recursive(leafProgOne);

export const leafProgTwo = ZkProgram({
  name: 'leaf-prog-two',
  publicInput: Field,
  publicOutput: Field,
  methods: {
    initLeaf: {
      privateInputs: [],
      async method(publicInput: Field) {
        return { publicOutput: publicInput.mul(Field(2)) };
      }
    },
    mergeOne: {
      privateInputs: [],
      async method(publicInput: Field) {
        let x: Field = await leafProgOneRec.initLeaf(publicInput);
        return { publicOutput: x.mul(3) };
      }
    },
    mergeTwo: {
      privateInputs: [],
      async method(publicInput: Field) {
        let x: Field = await leafProgTwoRec.initLeaf(publicInput);
        let y: Field = await leafProgTwoRec.mergeOne(publicInput);
        return { publicOutput: x.mul(y) };
      }
    }
  }
})
export let leafProgTwoRec = Experimental.Recursive(leafProgTwo);

export const mergerProg = ZkProgram({
  name: 'merger-prog',
  publicInput: Field,
  publicOutput: Field,
  methods: {
    initLeafZero: {
      privateInputs: [leafProgZero.Proof],
      async method(publicInput: Field, proof: Proof<Field, Field>) {
        proof.verify();
        proof.publicInput.assertEquals(publicInput);
        return { publicOutput: proof.publicOutput };
      }
    },
    initLeafOne: {
      privateInputs: [leafProgOne.Proof],
      async method(publicInput: Field, proof: Proof<Field, Field>) {
        proof.verify();
        // proof.publicInput.assertEquals(publicInput);
        return { publicOutput: proof.publicOutput };
      }
    },
    initLeafTwo: {
      privateInputs: [leafProgTwo.Proof],
      async method(publicInput: Field, proof: Proof<Field, Field>) {
        proof.verify();
        // proof.publicInput.assertEquals(publicInput);
        return { publicOutput: proof.publicOutput };
      }
    },
    mergeNodes: {
      privateInputs: [SelfProof, SelfProof],
      async method(publicInput: Field, proof1: SelfProof<Field, Field>, proof2: SelfProof<Field,Field>) {
        proof1.verify();
        proof2.verify();
        // proof1.publicInput.assertEquals(publicInput);
        // proof1.publicOutput.assertEquals(proof2.publicInput);
        return { publicOutput: proof2.publicOutput };
      }
    }
  }
});

export const casualProg = ZkProgram({
  name: 'casual-prog',
  publicInput: Undefined,
  publicOutput: Field,
  methods: {
    superCasualMethod: {
      privateInputs: [mergerProg.Proof],
      async method(proof: Proof<Field, Field>) {
        proof.verify();
        return { publicOutput: proof.publicOutput.add(1) };
      }
    }
  }
})

const proofsEnabled = true;
async function main() {
  const { verificationKey: leaf0VerificationKey } = 
    await mytime('Compiling LeafProg', () => leafProgZero.compile({ proofsEnabled }));
  const { verificationKey: leaf1VerificationKey  } = 
    await mytime('Compiling LeafProgRec', () => leafProgOne.compile({ proofsEnabled }));
  const { verificationKey: leaf2VerificationKey  } = 
    await mytime('Compiling LeafProgRec', () => leafProgTwo.compile({ proofsEnabled }));
  const { verificationKey: mergerVerificationKey } = 
    await mytime('Compiling Merger', () => mergerProg.compile({ proofsEnabled }));
  const { verificationKey: casualVerificationKey } = 
    await mytime('Compiling Casual', () => casualProg.compile({ proofsEnabled }));

  const { proof: leafProg0Proof0 } = 
    await mytime('Create leafProg0Proof0', () => leafProgZero.initLeaf(Field.from(1)));
  const { proof: leafProg1Proof0 } =
    await mytime('Create leafProg1Proof0', () => leafProgOne.initLeaf(Field.from(1)));
  const { proof: leafProg2Proof0 } =
    await mytime('Create leafProg2Proof0', () => leafProgTwo.initLeaf(Field.from(1)));
  const { proof: leafProg1Proof1 } =
    await mytime('Create leafProg1Proof1', () => leafProgOne.mergeOne(Field.from(1)));
  const { proof: leafProg2Proof1 } =
    await mytime('Create leafProg2Proof1', () => leafProgTwo.mergeOne(Field.from(1)));
  const { proof: leafProg2Proof2 } =
    await mytime('Create leafProg2Proof1', () => leafProgTwo.mergeTwo(Field.from(1)));


  // WORKS
  const { proof: mergerL0P0 } = 
    await mytime('Create mergerL0P0', () => mergerProg.initLeafZero(leafProg0Proof0.publicInput, leafProg0Proof0));

  // WORKS
  const { proof: mergerL1P0 } =
    await mytime('Create mergerL1P0', () => mergerProg.initLeafOne(leafProg1Proof0.publicInput, leafProg1Proof0));
  
  // WORKS
  const { proof: mergerL2P0 } =
    await mytime('Create mergerL2P0', () => mergerProg.initLeafTwo(leafProg2Proof0.publicInput, leafProg2Proof0));

  // THROWS AN ERROR
  // const { proof: mergerL1P1 } =
  //   await mytime('Create mergerL1P1', () => mergerProg.initLeafOne(leafProg1Proof1.publicInput, leafProg1Proof1));

  // WORKS
  const { proof: mergerL2P1 } =
    await mytime('Create mergerL2P1', () => mergerProg.initLeafTwo(leafProg2Proof1.publicInput, leafProg2Proof1));

  // WORKS
  const { proof: mergerL2P2 } =
    await mytime('Create mergerL2P2', () => mergerProg.initLeafTwo(leafProg2Proof2.publicInput, leafProg2Proof2));
  
  
  let left = mergerL0P0;
  let right = mergerL1P0;

  const { proof: mergedProof } =
    await mytime('Merge Proofs', () => mergerProg.mergeNodes(
      left.publicInput, left, right
    ));

  const { proof: casualProgProof } =
    await mytime('Create CasualProof', () => casualProg.superCasualMethod(mergedProof));

  const isCasualProofVerified = 
    await mytime('verify CasualProof', () => verify(casualProgProof, casualVerificationKey));
  console.log({ isCasualProofVerified });
}

await main();