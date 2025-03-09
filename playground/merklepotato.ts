import {
  DynamicProof,
  FeatureFlags,
  Field,
  MerkleTree,
  MerkleWitness,
  Proof,
  SelfProof,
  Struct,
  VerificationKey,
  ZkProgram,
  verify,
} from 'o1js';

/**
 * This example showcases how DynamicProofs can be used along with a merkletree that stores
 * the verification keys that can be used to verify it.
 * The MainProgram has two methods, addSideloadedProgram that adds a given verification key
 * to the tree, and validateUsingTree that uses a given tree leaf to verify a given child-proof
 * using the verification tree stored under that leaf.
 */

const sideloadedPrograms = [];
for (let i = 0; i < 8; ++i) {
  sideloadedPrograms.push(
    ZkProgram({
      name: 'childProgram' + i,
      publicInput: Field,
      publicOutput: Field,
      methods: {
        compute: {
          privateInputs: [Field],
          async method(publicInput: Field, privateInput: Field) {
            return {
              publicOutput: publicInput.add(privateInput),
            };
          },
        },
        assertAndAdd: {
          privateInputs: [Field],
          async method(publicInput: Field, privateInput: Field) {
            // this uses assert to test range check gates and their feature flags
            publicInput.assertLessThanOrEqual(privateInput);
            return { publicOutput: publicInput.add(privateInput) };
          },
        },
      },
    })
  );
}

// given a zkProgram, we compute the feature flags that we need in order to verify proofs that were generated
const featureFlags = await FeatureFlags.fromZkProgram(sideloadedPrograms[0]);

class SideloadedProgramProof extends DynamicProof<Field, Field> {
  static publicInputType = Field;
  static publicOutputType = Field;
  static maxProofsVerified = 0 as const;

  // we use the feature flags that we computed from the `sideloadedProgram` ZkProgram
  static featureFlags = featureFlags;
}

const tree = new MerkleTree(64);
class MerkleTreeWitness extends MerkleWitness(64) {}

class MainProgramState extends Struct({
  treeRoot: Field,
  state: Field,
}) {}

const mainProgram = ZkProgram({
  name: 'mainProgram',
  publicInput: MainProgramState,
  publicOutput: MainProgramState,
  methods: {
    addSideloadedProgram: {
      privateInputs: [VerificationKey, MerkleTreeWitness],
      async method(
        publicInput: MainProgramState,
        vk: VerificationKey,
        merkleWitness: MerkleTreeWitness
      ) {
        // In practice, this method would be guarded via some access control mechanism
        const currentRoot = merkleWitness.calculateRoot(Field(0));
        publicInput.treeRoot.assertEquals(
          currentRoot,
          'Provided merklewitness not correct or leaf not empty'
        );
        const newRoot = merkleWitness.calculateRoot(vk.hash);

        return {
          publicOutput: new MainProgramState({
            state: publicInput.state,
            treeRoot: newRoot,
          }),
        };
      },
    },
    validateUsingTree: {
      privateInputs: [SelfProof, VerificationKey, MerkleTreeWitness, SideloadedProgramProof],
      async method(
        publicInput: MainProgramState,
        previous: Proof<MainProgramState, MainProgramState>,
        vk: VerificationKey,
        merkleWitness: MerkleTreeWitness,
        proof: SideloadedProgramProof
      ) {
        // Verify previous program state
        previous.publicOutput.state.assertEquals(publicInput.state);
        previous.publicOutput.treeRoot.assertEquals(publicInput.treeRoot);

        // Verify inclusion of vk inside the tree
        const computedRoot = merkleWitness.calculateRoot(vk.hash);
        publicInput.treeRoot.assertEquals(
          computedRoot,
          'Tree witness with provided vk not correct'
        );

        proof.verify(vk);

        // Compute new state
        proof.publicInput.assertEquals(publicInput.state);
        const newState = proof.publicOutput;
        return {
          publicOutput: new MainProgramState({
            treeRoot: publicInput.treeRoot,
            state: newState,
          }),
        };
      },
    },
  },
});


const programVks = [];
for (let i = 0; i < sideloadedPrograms.length; i++) {
  console.time('Compiling circuits... ' + i);
  const vk = (await sideloadedPrograms[i].compile()).verificationKey;
  console.timeEnd('Compiling circuits... ' + i);
  programVks.push(vk);
}
console.time('Compiling main program...');
const mainVk = (await mainProgram.compile()).verificationKey;
console.timeEnd('Compiling main program...');

const rootBefore = tree.getRoot();
let proof1 = { publicOutput: new MainProgramState({
  treeRoot: rootBefore,
  state: Field(0),
}) };
for (let i = 0; i < sideloadedPrograms.length; i++) {
  console.time('Proving deployment of side-loaded key ' + i);
  tree.setLeaf(BigInt(i+1), programVks[i].hash);
  const witness = new MerkleTreeWitness(tree.getWitness(BigInt(i+1)));
  const res = await mainProgram.addSideloadedProgram(
    proof1.publicOutput,
    programVks[i],
    witness
  );
  proof1 = res.proof;
  console.timeEnd('Proving deployment of side-loaded key ' + i);
}
let childProofs = [];
for (let i = 0; i < sideloadedPrograms.length; i++) {
  console.time('Proving child program execution ' + i);
  const res = await sideloadedPrograms[i].compute(Field(0), Field(i+10));
  console.timeEnd('Proving child program execution ' + i);
  childProofs.push(res.proof);
}

for (let i = 0; i < sideloadedPrograms.length; i++) {
  const witness = new MerkleTreeWitness(tree.getWitness(BigInt(i+1)));
  console.time('Proving verification inside main program ' + i);
  const res = await mainProgram.validateUsingTree(
    proof1.publicOutput,
    // @ts-ignore
    proof1,
    programVks[i],
    witness,
    SideloadedProgramProof.fromProof(childProofs[i])
  );
  console.timeEnd('Proving verification inside main program ' + i);
  const validProof = await verify(res.proof, mainVk);
  console.log('ok?', validProof);
}

console.log('Proving different method of child program');
let childProofs2 = [];
for (let i = 0; i < sideloadedPrograms.length; i++) {
  console.time('Proving child program execution ' + i);
  const res = await sideloadedPrograms[i].assertAndAdd(Field(0), Field(i+10));
  console.timeEnd('Proving child program execution ' + i);
  childProofs2.push(res.proof);
}

for (let i = 0; i < sideloadedPrograms.length; i++) {
  const witness = new MerkleTreeWitness(tree.getWitness(BigInt(i+1)));
  console.time('Proving verification inside main program ' + i);
  const res = await mainProgram.validateUsingTree(
    proof1.publicOutput,
    // @ts-ignore
    proof1,
    programVks[i],
    witness,
    SideloadedProgramProof.fromProof(childProofs2[i])
  );
  console.timeEnd('Proving verification inside main program ' + i);
  const validProof = await verify(res.proof, mainVk);
  console.log('ok?', validProof);
}