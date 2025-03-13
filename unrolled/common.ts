import { Field, Struct } from "o1js";

export class Out extends Struct({
  left: Field,
  right: Field,
  vkDigest: Field,
}) {}
