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
    initL0P0: {
      privateInputs: [],
      async method(publicInput: Field) {
        const x: Field = await leafProgZeroRec.initLeaf(publicInput);
        return { publicOutput: x };
      }
    },
    initL1P0: {
      privateInputs: [],
      async method(publicInput: Field) {
        const x: Field = await leafProgOneRec.initLeaf(publicInput);
        return { publicOutput: x };
      }
    },
    initL2P0: {
      privateInputs: [],
      async method(publicInput: Field) {
        const x: Field = await leafProgTwoRec.initLeaf(publicInput);
        return { publicOutput: x };
      }
    },
    initL1P1: {
      privateInputs: [],
      async method(publicInput: Field) {
        const x: Field = await leafProgOneRec.mergeOne(publicInput);
        return { publicOutput: x };
      }
    },
    initL2P1: {
      privateInputs: [],
      async method(publicInput: Field) {
        const x: Field = await leafProgTwoRec.mergeOne(publicInput);
        return { publicOutput: x };
      }
    },
    initL2P2: {
      privateInputs: [],
      async method(publicInput: Field) {
        const x: Field = await leafProgTwoRec.mergeTwo(publicInput);
        return { publicOutput: x };
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

  // const { proof: leafProg0Proof0 } = 
  //   await mytime('Create leafProg0Proof0', () => leafProgZero.initLeaf(Field.from(1)));
  // const { proof: leafProg1Proof0 } =
  //   await mytime('Create leafProg1Proof0', () => leafProgOne.initLeaf(Field.from(1)));
  // const { proof: leafProg2Proof0 } =
  //   await mytime('Create leafProg2Proof0', () => leafProgTwo.initLeaf(Field.from(1)));
  // const { proof: leafProg1Proof1 } =
  //   await mytime('Create leafProg1Proof1', () => leafProgOne.mergeOne(Field.from(1)));
  // const { proof: leafProg2Proof1 } =
  //   await mytime('Create leafProg2Proof1', () => leafProgTwo.mergeOne(Field.from(1)));
  // const { proof: leafProg2Proof2 } =
  //   await mytime('Create leafProg2Proof1', () => leafProgTwo.mergeTwo(Field.from(1)));

  // const isLeaf1Verified = 
  //   await mytime('verify Leaf1Proof', () => verify(leafProgProof1, leafVerificationKey));
  // console.log({ isLeaf1Verified });

  const methods = ['initL0P0', 'initL1P0', 'initL2P0', 'initL1P1', 'initL2P1', 'initL2P2'];

  const leafs: { [k: string]: Proof<Field,Field> } = {
    // mergerL0P0,
    // mergerL1P0,
    // mergerL2P0,
    // mergerL1P1,
    // mergerL2P1,
    // mergerL2P2,
  };

  for (let i = 0 ; i < methods.length; i++) {
    const method = methods[i];
    const outName = `merger${method.substring(4)}`;
    try {
      const { proof: mergerProof } =
        // @ts-ignore
        await mytime(`Create ${outName}`, () => mergerProg[method](Field.from(1)));
      leafs[outName] = mergerProof;
    } catch (e) {
      console.error(`Ignoring error creating proof for ${outName}:`, e);

      // ONLY L1P1 THROWS AN ERROR.
    }
  }
  
  const leafKeys = Object.keys(leafs);
  for (let i = 0 ; i < leafKeys.length; i++) {
    for (let j = i + 1; j < leafKeys.length; j++) {
      const names = `${leafKeys[i]} and ${leafKeys[j]}`;
      try {
        const left = leafs[leafKeys[i]];
        const right = leafs[leafKeys[j]];

        const { proof: mergedProof } =
          await mytime(`Merge Proofs for ${names}`, () => mergerProg.mergeNodes(
            left.publicInput, left, right
          ));
        
        const { proof: casualProgProof } =
          await mytime(`Create CasualProof for ${names}`, () => casualProg.superCasualMethod(mergedProof));
        const isCasualProofVerified = 
          await mytime(`verify CasualProof for ${names}`, () => verify(casualProgProof, casualVerificationKey));
        console.log({ isCasualProofVerified });
      } catch (e) {
        console.error(`Ignoring error creating merged proofs for ${names}:`, e);
      }
    }
  }
}

await main();