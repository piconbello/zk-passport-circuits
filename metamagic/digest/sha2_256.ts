import { mytime } from "../../src/mytimer";
import { buildSha2ProgRunner } from "./shautils";

const NAME = 'sha2_256';
const proofsEnabled = process.env.PROOFS_ENABLED == '0' ? false : true;

const {
  program,
  runner
} = buildSha2ProgRunner(NAME);

const { iterate } = await program.analyzeMethods();
console.log(JSON.stringify(iterate.summary()));

const { verificationKey } = await mytime(
  `Compiling ${NAME} zkProgram`,
  async () => program.compile({ proofsEnabled })
);

export { program, runner, verificationKey };