// Import the native module. On web, it will be resolved to ExpoKryptom.web.ts
// and on native platforms to ExpoKryptom.ts
import ExpoKryptomModule from "./ExpoKryptomModule";

export namespace Aes {
  export async function generateKey(size: number): Promise<Uint8Array> {
    return ExpoKryptomModule.generateKey(size);
  }

  export async function encrypt(
    data: Uint8Array,
    key: Uint8Array,
    iv: Uint8Array | null,
  ): Promise<Uint8Array> {
    return ExpoKryptomModule.encrypt(data, key, iv);
  }

  export async function decrypt(
    ivAndEncryptedData: Uint8Array,
    key: Uint8Array,
  ): Promise<Uint8Array> {
    return ExpoKryptomModule.decrypt(ivAndEncryptedData, key);
  }
}
