import { Field, SelfProof, ZkProgram } from "o1js";


const makeMethods = (methodCnt: number) => {
  const methods: {[k:string]:any} = {
    init: {
      privateInputs: [Field],
      async method(value: Field) {
        value.assertEquals(Field.from(0));
        return { publicOutput: value };
      },
    }
  }
  for (let i = 1; i <= methodCnt; i++) {
    methods[`add${i}`] = {
      privateInputs: [SelfProof, Field],
      async method(proof: SelfProof<undefined, Field>, value: Field) {
        proof.verify()
        proof.publicOutput.add(i).assertEquals(value);
        return { publicOutput: value };
      },
    }
  }
  return methods;
}

for (let i = 0; i <= 6; i++) {
  const methodCnt = Math.pow(2, i);
  const programName = `Potato2**${i}`;
  console.log(`Creating program ${programName} with ${methodCnt+1} methods`);
  const program = ZkProgram({
    name: programName,
    publicOutput: Field,
    // @ts-ignore
    methods: makeMethods(methodCnt),
  });
  if (i === 1) {
    const analyzedMethods = await program.analyzeMethods();
    Object.entries(analyzedMethods).forEach(([name, analysis]) => {
      console.log(`${name}: ${JSON.stringify(analysis.summary())}`);
    });
  }
  console.log('Compiling program', programName);
  console.time(`Compiled ${programName}`)
  await program.compile();
  console.timeEnd(`Compiled ${programName}`);

  console.log(`Running program after running each of ${methodCnt+1} methods`);
  console.time(`Created proof for ${programName}`);
  // @ts-ignore
  let { proof }  = await program.init(Field.from(0));
  for (let i = 1; i <= methodCnt; ++i) {
    // @ts-ignore
    const res = await program[`add${i}`](proof, Field.from(proof.publicOutput.add(i)));
    proof = res.proof;
  }
  console.timeEnd(`Created proof for ${programName}`);

  console.log(`Verifying proof for ${programName}, its public output is ${proof.publicOutput.toString()}`);
  console.time(`Verified ${programName}`);
  await proof.verify();
  console.timeEnd(`Verified ${programName}`);

  console.log(`Running program after running each of ${methodCnt+1} methods twice`);
  console.time(`Created proof for ${programName}`);
  // @ts-ignore
  const res2 = await program.init(Field.from(0));
  proof = res2.proof;
  for (let i = 1; i <= methodCnt; ++i) {
    for (let j = 0; j < 2; ++j) {
      // @ts-ignore
      const res = await program[`add${i}`](proof, Field.from(proof.publicOutput.add(i)));
      proof = res.proof;
    }
  }
  console.timeEnd(`Created proof for ${programName}`);

  console.log(`Verifying proof for ${programName}, its public output is ${proof.publicOutput.toString()}`);
  console.time(`Verified ${programName}`);
  await proof.verify();
  console.timeEnd(`Verified ${programName}`);
}