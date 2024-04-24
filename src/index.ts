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
  encrypt: async (data: Uint8Array, key: RsaPublicKey) => {
    return await ExpoKryptomModule.encryptRsa(
      data,
      (key as NativeRsaPublicKey).public,
      key.algorithmIdentifier
    ) as Uint8Array;
  },
  decrypt: async (data: Uint8Array, key: RsaPrivateKey) => {
    return await ExpoKryptomModule.decryptRsa(
      data,
      (key as NativeRsaPrivateKey).private,
      key.algorithmIdentifier
    ) as Uint8Array;
  },
  exportPrivateKeyPkcs8: async (key: RsaPrivateKey) => {
    if (ExpoKryptomModule.needExports) {
      return await ExpoKryptomModule.exportPrivateKeyPkcs8Rsa(
        (key as NativeRsaPrivateKey).private,
        key.algorithmIdentifier
      ) as Uint8Array;
    }
    return (key as NativeRsaPrivateKey).private;
  },
  exportPrivateKeyJwk: async (key: RsaPrivateKey) => {
    return await ExpoKryptomModule.exportPrivateKeyJwkRsa(
      (key as NativeRsaPrivateKey).private,
      key.algorithmIdentifier
    ) as PrivateRsaKeyJwk;
  },
  exportPublicKeySpki: async (key: RsaPublicKey) => {
    if (ExpoKryptomModule.needExports) {
      return await ExpoKryptomModule.exportPublicKeySpkiRsa(
        (key as NativeRsaPublicKey).public,
        key.algorithmIdentifier
      ) as Uint8Array;
    }
    return (key as NativeRsaPublicKey).public;
  },
  exportPublicKeyJwk: async (key: RsaPublicKey) => {
    return await ExpoKryptomModule.exportPublicKeyJwkRsa(
      (key as NativeRsaPublicKey).public,
      key.algorithmIdentifier
    ) as PublicRsaKeyJwk;
  },
  importPrivateKeyPkcs8: async (privateKeyPkcs8: Uint8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaPrivateKey> => {
    if (ExpoKryptomModule.needExports) {
      return await ExpoKryptomModule.importPrivateKeyPkcs8Rsa(privateKeyPkcs8, algorithmIdentifier);
    }
    const res: NativeRsaPrivateKey = {
      private: privateKeyPkcs8,
      algorithmIdentifier
    }
    return res;
  },
  importPrivateKeyJwk: async (privateKey: PrivateRsaKeyJwk, algorithmIdentifier: RsaAlgorithm) => {
    return await ExpoKryptomModule.importPrivateKeyJwkRsa(privateKey, algorithmIdentifier) as RsaPrivateKey;
  },
  importPublicKeySpki: async (publicKeySpki: Uint8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaPublicKey> => {
    if (ExpoKryptomModule.needExports) {
      return await ExpoKryptomModule.importPublicKeySpkiRsa(publicKeySpki, algorithmIdentifier);
    }
    const res: NativeRsaPublicKey = {
      public: publicKeySpki,
      algorithmIdentifier
    }
    return res;
  },
  importPublicKeyJwk: async (publicKey: PublicRsaKeyJwk, algorithmIdentifier: RsaAlgorithm): Promise<RsaPublicKey> => {
    return await ExpoKryptomModule.importPublicKeyJwkRsa(publicKey, algorithmIdentifier);
  },
  importKeyPair: async (privateKeyPkcs8: Uint8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaKeyPair> => {
    return await ExpoKryptomModule.importKeyPairRsa(privateKeyPkcs8, algorithmIdentifier);
  },
  signature: async (data: Uint8Array, key: RsaPrivateKey): Promise<Uint8Array> => {
    return await ExpoKryptomModule.signatureRsa(data, (key as NativeRsaPrivateKey).private, key.algorithmIdentifier);
  },
  verify: async (signature: Uint8Array, data: Uint8Array, key: RsaPublicKey): Promise<boolean> => {
    return await ExpoKryptomModule.verifyRsa(signature, data, (key as NativeRsaPublicKey).public, key.algorithmIdentifier);
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

type NativeRsaKeyPair = {
  public: Uint8Array;
  private: Uint8Array;
  algorithmIdentifier: RsaAlgorithm;
};

export type HmacKey = {
  key: Uint8Array;
  algorithmIdentifier: HmacAlgorithm;
};

type NativeRsaPrivateKey = {
  private: Uint8Array;
  algorithmIdentifier: RsaAlgorithm;
};

type NativeRsaPublicKey = {
  public: Uint8Array;
  algorithmIdentifier: RsaAlgorithm;
};

export interface RsaKeyPair {
  algorithmIdentifier: RsaAlgorithm
}

export interface RsaPrivateKey {
  algorithmIdentifier: RsaAlgorithm
}

export interface RsaPublicKey {
  algorithmIdentifier: RsaAlgorithm
}

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
