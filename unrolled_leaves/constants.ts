import {
  Bytes,
  createEcdsa,
  createForeignCurve,
  Field,
  UInt8,
  Crypto,
  Struct,
} from "o1js";

import { DynamicBytes, StaticArray } from "@egemengol/mina-credentials/dynamic";
import { State as ContainsState } from "../unrolled_meta/contains";

const LDS_256_MAX_LENGTH = 800;
const LDS_512_MAX_LENGTH = 1200;

export class DG1_TD3 extends Bytes(93) {}
export class LDS_256 extends DynamicBytes({ maxLength: LDS_256_MAX_LENGTH }) {}
export class LDS_512 extends DynamicBytes({ maxLength: LDS_512_MAX_LENGTH }) {}
export class SIGNED_ATTRS_256 extends Bytes(74) {}
export class SIGNED_ATTRS_512 extends Bytes(74) {}

export class TBS extends DynamicBytes({ maxLength: 900 }) {}
export class SIGNED_ATTRS extends DynamicBytes({ maxLength: 200 }) {}

export class Bytes65 extends Bytes(65) {}
export class Static65 extends StaticArray(UInt8, 65) {}

export class Bytes32 extends Bytes(32) {}
export class Bytes64 extends Bytes(64) {}

export class DynSignedAttrs extends DynamicBytes({ maxLength: 200 }) {}

export const Field3 = StaticArray(Field, 3);
export class Secp256r1 extends createForeignCurve(
  Crypto.CurveParams.Secp256r1,
) {}
export class EcdsaSecp256r1 extends createEcdsa(Secp256r1) {}
