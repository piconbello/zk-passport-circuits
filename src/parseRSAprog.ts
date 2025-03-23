import { ZkProgram } from "o1js";
import { ModulusBytes, parseModulusIntoLimbs } from "./parseRsaModulusNew";
import { mapObject } from "../tests/common";

export const ParseRSA = ZkProgram({
  name: "parseRSA",

  methods: {
    parseRSA: {
      privateInputs: [ModulusBytes],
      async method(modulus: ModulusBytes) {
        parseModulusIntoLimbs(modulus);
      },
    },
  },
});

await ParseRSA.compile();
console.log(
  mapObject(await ParseRSA.analyzeMethods(), (m) => m.summary()["Total rows"]),
);
