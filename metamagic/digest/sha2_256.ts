import { FeatureFlags, Poseidon, VerificationKey } from "o1js";
import { mytime } from "../../src/mytimer";
import { buildMerger } from "./selfmerger";
import { buildSha2ProgRunner } from "./shautils2";

const NAME = 'sha2_256';
const proofsEnabled = process.env.PROOFS_ENABLED == '0' ? false : true;

const {
  program,
  runner
} = buildSha2ProgRunner(NAME);

const { verificationKey } = await mytime(
  `Compiling ${NAME} zkProgram`,
  async () => program.compile({ proofsEnabled })
);
console.log(await FeatureFlags.fromZkProgram(program));
console.log('maxproofsverif', await program.maxProofsVerified());

const { iterate } = await program.analyzeMethods();
console.log(JSON.stringify(iterate.summary()));

// const merger = buildMerger(verificationKey);
const merger = (a) => a[a.length - 1];

const vkHash = Poseidon.hashPacked(VerificationKey, verificationKey);

export { program, runner, merger, verificationKey, vkHash };