// Import the native module. On web, it will be resolved to ExpoKryptom.web.ts
// and on native platforms to ExpoKryptom.ts
import ExpoKryptomModule from "./ExpoKryptomModule";

export const Aes = {
  generateKey: async (size: number) => {
    return await ExpoKryptomModule.generateKeyAes(size) as Uint8Array;
  },
  encrypt: async (data: Uint8Array, key: Uint8Array, iv: Uint8Array | null) => {
    return ExpoKryptomModule.encryptAes(data, key, iv) as Uint8Array;
  },
  decrypt: async (ivAndEncryptedData: Uint8Array, key: Uint8Array) => {
    return await ExpoKryptomModule.decryptAes(ivAndEncryptedData, key) as Uint8Array;
  },
};

export const Rsa = {
  generateKey: async (algorithmIdentifier: string, size: number) => {
    return await ExpoKryptomModule.generateKeyRsa(algorithmIdentifier, size) as RsaKeyPair;
  },
  encrypt: async (data: Uint8Array, key: { public: Uint8Array, algorithmIdentifier: RsaEncryptionAlgorithm }) => {
    return await ExpoKryptomModule.encryptRsa(data, key.public, key.algorithmIdentifier) as Uint8Array;
  },
  decrypt: async (data: Uint8Array, key: { private: Uint8Array, algorithmIdentifier: RsaEncryptionAlgorithm }) => {
    return await ExpoKryptomModule.decryptRsa(data, key.private, key.algorithmIdentifier) as Uint8Array;
  },
  exportPrivateKeyPkcs8: async (key: { private: Uint8Array, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.exportPrivateKeyPkcs8(key.private, key.algorithmIdentifier) as Uint8Array;
  },
  exportPrivateKeyJwk: async (key: { private: Uint8Array, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.exportPrivateKeyJwk(key.private, key.algorithmIdentifier) as PrivateRsaKeyJwk;
  },
  exportPublicKeySpki: async (key: { public: Uint8Array, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.exportPublicKeySpki(key.public, key.algorithmIdentifier) as Uint8Array;
  },
  exportPublicKeyJwk: async (key: { public: Uint8Array, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.exportPublicKeyJwk(key.public, key.algorithmIdentifier) as PublicRsaKeyJwk;
  },
  importPrivateKeyPkcs8: async (key: { private: Uint8Array, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.importPrivateKeyPkcs8(key.private, key.algorithmIdentifier) as Uint8Array;
  },
  importPrivateKeyJwk: async (key: { private: PrivateRsaKeyJwk, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.importPrivateKeyJwk(key.private, key.algorithmIdentifier) as Uint8Array;
  },
  importPublicKeySpki: async (key: { public: Uint8Array, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.importPublicKeySpki(key.public, key.algorithmIdentifier) as Uint8Array;
  },
  importPublicKeyJwk: async (key: { public: PublicRsaKeyJwk, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.importPublicKeyJwk(key.public, key.algorithmIdentifier) as Uint8Array;
  },
  importKeyPair: async (key: { private: Uint8Array, algorithmIdentifier: RsaAlgorithm }) => {
    return await ExpoKryptomModule.importKeyPair(key.private, key.algorithmIdentifier) as RsaKeyPair;
  },
  signature: async (data: Uint8Array, key: { private: Uint8Array, algorithmIdentifier: RsaSignatureAlgorithm }) => {
    return await ExpoKryptomModule.signatureRsa(data, key.private, key.algorithmIdentifier) as Uint8Array;
  },
  verify: async (signature: Uint8Array, data: Uint8Array, key: { publicKey: Uint8Array, algorithmIdentifier: String }) => {
    return await ExpoKryptomModule.verifyRsa(signature, data, key.publicKey, key.algorithmIdentifier) as boolean;
  },
};

export const Hmac = {
  generateKey: async (algorithmIdentifier: HmacAlgorithm) => {
    return await ExpoKryptomModule.generateKeyHmac(algorithmIdentifier) as HmacKey;
  },
  sign: async (data: Uint8Array, key: { key: Uint8Array, algorithmIdentifier: HmacAlgorithm }) => {
    return await ExpoKryptomModule.signHmac(key.algorithmIdentifier, key.key, data) as Uint8Array;
  },
  verify: async (signature: Uint8Array, data: Uint8Array, key: { key: Uint8Array, algorithmIdentifier: HmacAlgorithm }) => {
    return await ExpoKryptomModule.verifyHmac(key.algorithmIdentifier, key.key, signature, data) as boolean;
  },
}

export const StrongRandom = {
  randomBytes: (length: number) => {
    return ExpoKryptomModule.randomBytes(length) as Uint8Array;
  },
  randomUUID: () => {
    return ExpoKryptomModule.randomUUID() as string;
  },
}

export const Digest = {
  sha256: async (data: Uint8Array) => {
    return await ExpoKryptomModule.sha256(data) as Uint8Array;
  },
}

export type RsaEncryptionAlgorithm = "OaepWithSha1" | "OaepWithSha256";
export type RsaSignatureAlgorithm = "PssWithSha256";
export type RsaAlgorithm = RsaEncryptionAlgorithm | RsaSignatureAlgorithm
export type HmacAlgorithm = "HmacSha512"

export type RsaKeyPair = {
  public: Uint8Array;
  private: Uint8Array;
  algorithmIdentifier: RsaAlgorithm;
};

export type HmacKey = {
  key: Uint8Array;
  algorithmIdentifier: HmacAlgorithm;
};

export type PrivateRsaKeyJwk = {
  alg: string
  d: string
  dp: string
  dq: string
  e: string
  ext: boolean
  key_ops: string[]
  n: string
  p: string
  q: string
  qi: string
}

export type PublicRsaKeyJwk = {
  alg: string
  e: string
  ext: boolean
  key_ops: string[]
  n: string
}
