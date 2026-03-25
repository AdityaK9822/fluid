import { join } from "path";

interface NativeSignerBinding {
  signPayload(secret: string, payload: Buffer): Promise<Buffer>;
}

const nativeModulePath = join(__dirname, "../../fluid_signer.node");

export const nativeSigner = require(nativeModulePath) as NativeSignerBinding;
