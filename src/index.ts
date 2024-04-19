// Import the native module. On web, it will be resolved to ExpoKryptom.web.ts
// and on native platforms to ExpoKryptom.ts
import ExpoKryptomModule from "./ExpoKryptomModule";

const Aes = {
  generateKey: async (size: number) => {
    return ExpoKryptomModule.generateKeyAes(size);
  },
  encrypt: async (data: Uint8Array, key: Uint8Array, iv: Uint8Array | null) => {
    return ExpoKryptomModule.encryptAes(data, key, iv);
  },
  decrypt: async (ivAndEncryptedData: Uint8Array, key: Uint8Array) => {
    return ExpoKryptomModule.decryptAes(ivAndEncryptedData, key);
  },
};

const Rsa = {
  generateKey: async (algorithmIdentifier: string, size: number) => {
    return ExpoKryptomModule.generateKeyRsa(algorithmIdentifier, size);
  },
  // encrypt: async (data: Uint8Array, key: Uint8Array) => {
  //   return ExpoKryptomModule.encryptRsa(data, key);
  // },
  // decrypt: async (data: Uint8Array, key: Uint8Array) => {
  //   return ExpoKryptomModule.decryptRsa(data, key);
  // },
};

export { Aes, Rsa };
