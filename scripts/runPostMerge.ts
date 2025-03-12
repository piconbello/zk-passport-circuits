import { Field, DynamicProof, FeatureFlags, ZkProgram, Proof, SelfProof, Poseidon, verify, Undefined } from "o1js";
import { mytime } from "../src/mytimer";

class DynLeafProof extends DynamicProof<Field, Field> {
  static publicInputType = Field;
  static publicOutputType = Field;
  static maxProofsVerified = 0 as const;

  static featureFlags = FeatureFlags.allMaybe;
}

export const leafProg = ZkProgram({
  name: 'leaf-prog',
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

export const leafProgRec = ZkProgram({
  name: 'leaf-prog-rec',
  publicInput: Field,
  publicOutput: Field,
  methods: {
    initLeaf: {
      privateInputs: [],
      async method(publicInput: Field) {
        return { publicOutput: publicInput.mul(Field(2)) };
      }
    },
    iterate: {
      privateInputs: [SelfProof],
      async method(publicInput: Field, proof: SelfProof<Field, Field>) {
        proof.verify();
        return { publicOutput: proof.publicOutput.mul(publicInput) };
      }
    }
  }
})

export const mergerProg = ZkProgram({
  name: 'merger-prog',
  publicInput: Field,
  publicOutput: Field,
  methods: {
    initLeaf: {
      privateInputs: [leafProg.Proof],
      async method(publicInput: Field, proof: Proof<Field, Field>) {
        proof.verify();
        proof.publicInput.assertEquals(publicInput);
        return { publicOutput: proof.publicOutput };
      }
    },
    initLeafRec: {
      privateInputs: [leafProgRec.Proof],
      async method(publicInput: Field, proof: Proof<Field, Field>) {
        proof.verify();
        proof.publicInput.assertEquals(publicInput);
        return { publicOutput: proof.publicOutput };
      }
    },
    mergeNodes: {
      privateInputs: [SelfProof, SelfProof],
      async method(publicInput: Field, proof1: SelfProof<Field, Field>, proof2: SelfProof<Field,Field>) {
        proof1.verify();
        proof2.verify();
        proof1.publicInput.assertEquals(publicInput);
        proof1.publicOutput.assertEquals(proof2.publicInput);
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
  const { verificationKey: leafVerificationKey } = 
    await mytime('Compiling LeafProg', () => leafProg.compile({ proofsEnabled }));
  const { verificationKey: leafRecVerificationKey  } = 
    await mytime('Compiling LeafProgRec', () => leafProgRec.compile({ proofsEnabled }));
  const { verificationKey: mergerVerificationKey } = 
    await mytime('Compiling Merger', () => mergerProg.compile({ proofsEnabled }));
  const { verificationKey: casualVerificationKey } = 
    await mytime('Compiling Casual', () => casualProg.compile({ proofsEnabled }));

  const { proof: leafProgProof1 } = 
    await mytime('Create LeafProgProof1', () => leafProg.initLeaf(Field.from(1)));
  const { proof: leafProgProof2 } =
    await mytime('Create LeafProgProof2', () => leafProg.initLeaf(Field.from(2)));

  // const isLeaf1Verified = 
  //   await mytime('verify Leaf1Proof', () => verify(leafProgProof1, leafVerificationKey));
  // console.log({ isLeaf1Verified });

  const { proof: leafProgRecProof0 } = 
    await mytime('Create LeafProgRecProof0', () => leafProgRec.initLeaf(Field.from(2)));

  // const isLeafProgRecProof0Verified = 
  //   await mytime('verify LeafProgRecProof0', () => verify(leafProgRecProof0, leafRecVerificationKey));
  // console.log({ isLeafProgRecProof0Verified });

  const { proof: leafProgRecProof1 } =
    await mytime('Iterate LeafProgRecProof', () => leafProgRec.iterate(
      Field.from(2), leafProgRecProof0
    ));
  
  // const isLeafProgRecProof1Verified =
  //   await mytime('verify LeafProgRecProof1', () => verify(leafProgRecProof1, leafRecVerificationKey));
  // console.log({ isLeafProgRecProof1Verified });
  
  const { proof: leafProof1 } = 
    await mytime('Create LeafProof1 from Merger', () => mergerProg.initLeaf(
      leafProgProof1.publicInput, leafProgProof1
    ))

  // WORKS
  // const { proof: leafProof2 } =
  //   await mytime('Create LeafProof2 from Merger', () => mergerProg.initLeaf(
  //     leafProgProof2.publicInput, leafProgProof2
  //   ));

  // WORKS
  const { proof: leafProof2 } =
    await mytime('Create LeafProof2 from Merger', () => mergerProg.initLeafRec(
      leafProgRecProof0.publicInput, leafProgRecProof0
    ));

  // DOESN'T WORK!
  // const { proof: leafProof2 } =
  //   await mytime('Create LeafProof2 from Merger', () => mergerProg.initLeafRec(
  //     leafProgRecProof1.publicInput, leafProgRecProof1
  //   ));
  
  const { proof: mergedProof } =
    await mytime('Merge Proofs', () => mergerProg.mergeNodes(
      leafProof1.publicInput, leafProof1, leafProof2
    ));

  // const isMergerVerified = 
  //   await mytime('verify mergedProof', () => verify(mergedProof, mergerVerificationKey));
  // console.log({ isMergerVerified });

  const { proof: casualProgProof } =
    await mytime('Create CasualProof', () => casualProg.superCasualMethod(mergedProof));

  const isCasualProofVerified = 
    await mytime('verify CasualProof', () => verify(casualProgProof, casualVerificationKey));
  console.log({ isCasualProofVerified });
}

await main();