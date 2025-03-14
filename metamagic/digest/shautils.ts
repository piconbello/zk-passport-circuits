import { ZkProgram, Struct, SelfProof, Field, Poseidon, Bytes, Gadgets, Provable, Keccak, UInt32, UInt64, type FlexibleBytes, Bool } from "o1js";
// import { SHA2 } from '@egemengol/mina-credentials'

export const getDigestCommitment = (digest:FlexibleBytes, salt: Field) => 
  Poseidon.hash([...Bytes.from(digest).toFields(), salt]);

export const buildSha2ProgRunner = (name: string) => {
  let algLength: 224 | 256 | 512 | 384;
  switch(name) {
    case'sha2_224':
      algLength = 224;
      break;
    case 'sha2_256':
      algLength = 256;
      break;
    case 'sha2_384':
      algLength = 384;
      break;
    case 'sha2_512':
      algLength = 512;
      break;
    default:
      throw new Error(`Unsupported SHA algorithm: ${name}`);
  }

  const initialState = Gadgets.SHA2.initialState(algLength);
  // 8 blocks of 32/64-bit words

  const itemType = initialState[0].constructor as (typeof UInt32 | typeof UInt64);

  const initialStateComm = Poseidon.hash(initialState.map(k => k.value));

  // FUTURE COMM THINGY:
  // hash => O1 (O2 (O3 (O4 (O5 (O6)))))

  class ShaInput extends Struct({
    // remainingBlockCount: Field, // Number of remaining blocks
    state: Provable.Array(itemType, 8), // State after processing each block
    salt: Field, // Salt :)
    futureComm: Field,

    block: Provable.Array(itemType, 16), // Current block
    prevComm: Field, // Commitment for previous proof input. (prev proof public input)
  }){}

  class ShaOutput extends Struct({
    // remainingBlockCount: Field, // Number of remaining blocks
    stateComm: Field,
    salt: Field, // Salt :)
    futureComm: Field,
  }){}

  const shaProgram = ZkProgram({
    name,
    publicInput: Field,
    publicOutput: Field,
    methods: {
      iterate: {
        privateInputs: [SelfProof, ShaInput],
        async method(inputComm: Field, previous: SelfProof<Field, Field>, input: ShaInput): Promise<{ publicOutput: Field }> {
          Poseidon.hashPacked(ShaInput, input).assertEquals(inputComm);
          const stateComm = Poseidon.hash(input.state.map(k => k.value));
          const isInitial = stateComm.equals(initialStateComm);
          // isInitial: Bool = input.prevComm.equals(0);
          let isNotInitial: Bool = isInitial.not();
          Provable.log('is initial', isInitial);

          previous.verifyIf(isNotInitial);
          previous.publicInput.assertEquals(input.prevComm);

          Provable.log('input block', input.block);
          const W = Gadgets.SHA2.messageSchedule(algLength, input.block);
          const nextState = Gadgets.SHA2.compression(algLength, input.state, W);
          const nextStateComm = Poseidon.hash(nextState.map(k => k.value));

          const prevFutureComm = Poseidon.hash([nextStateComm, input.futureComm]);
          const prevOutput = new ShaOutput({
            // remainingBlockCount: input.remainingBlockCount,
            stateComm: stateComm,
            salt: input.salt,
            futureComm: prevFutureComm,
          });
          Poseidon.hashPacked(ShaOutput, prevOutput).assertEquals(previous.publicOutput);

          const nextOutput = new ShaOutput({
            // remainingBlockCount: input.remainingBlockCount.sub(1),
            stateComm: nextStateComm,
            salt: input.salt,
            futureComm: input.futureComm,
          });
          const nextOutputHash = Poseidon.hashPacked(ShaOutput, nextOutput);

          const digest = Bytes.from(nextState.map((x) => x.toBytesBE()).flat());
          digest.bytes = digest.bytes.slice(0, algLength / 8);
          const digestComm = getDigestCommitment(digest, input.salt);

          // const isFinal: Bool = nextOutput.remainingBlockCount.equals(0);
          const isFinal: Bool = nextOutput.futureComm.equals(0);

          Provable.log('is final', isFinal, nextOutput.futureComm);
          const publicOutput = Provable.if(
            isFinal,
            digestComm,
            nextOutputHash
          );
          Provable.log('publicOutput', publicOutput);
          
          return { publicOutput };
        },
      }
    }
  });

  let runner = async (salt: Field, data: FlexibleBytes) => {
    const messageBlocks = Gadgets.SHA2.padding(algLength, data);
    let state = initialState;
    let futureComm = Field.from(0);
    const stateCommitments = [initialStateComm];
    const futureCommitments = [futureComm];
    const N = messageBlocks.length;
    for (let i = 0; i < N; i++) {
      const W = Gadgets.SHA2.messageSchedule(algLength, messageBlocks[i]);
      state = Gadgets.SHA2.compression(algLength, state, W);
      stateCommitments.push(Poseidon.hash(state.map(k => k.value)));
    }
    for (let i = stateCommitments.length - 1; i >= 0; i--) {
      futureComm = Poseidon.hash([stateCommitments[i], futureComm]);
      futureCommitments.push(futureComm);
    }
    futureCommitments.reverse();

    const initialOutput = new ShaOutput({
      // remainingBlockCount: Field.from(N+1),
      stateComm: initialStateComm,
      salt: salt,
      futureComm: futureCommitments[0],
    });
    const maxProofsVerified = await shaProgram.maxProofsVerified();

    let proof = await shaProgram.Proof.dummy(
      Field.from(0), 
      Poseidon.hashPacked(ShaOutput, initialOutput), 
      maxProofsVerified
    );

    state = initialState;
    for (let i = 0; i < N; i++) {
      const input = new ShaInput({
        // remainingBlockCount: Field.from(N - i - 1),
        state: state,
        salt: salt,
        futureComm: futureCommitments[i+1],
        block: messageBlocks[i],
        prevComm: proof.publicInput,
      });
      console.log('before iteration', i+1, N);
      console.time(`${name} iteration ${i+1} / ${N}`);
      const res = await shaProgram.iterate(
        Poseidon.hashPacked(ShaInput, input), 
        proof, 
        input
      );
      console.timeEnd(`${name} iteration ${i+1} / ${N}`);
      proof = res.proof;
    }

    console.log(
      'Final proof output is correct',
      proof.publicOutput.equals(
        getDigestCommitment(
          Gadgets.SHA2.hash(algLength, data),
          salt
        )
      ).toBoolean()
    );

    return proof;
  }

  return {
    program: shaProgram,
    runner,
  };
}