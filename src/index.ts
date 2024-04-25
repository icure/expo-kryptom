// Import the native module. On web, it will be resolved to ExpoKryptom.web.ts
// and on native platforms to ExpoKryptom.ts
import ExpoKryptomModule from "./ExpoKryptomModule";

const rsaKeyNeedsExport = ExpoKryptomModule.rsaKeyNeedsExport;

export const Aes = {
  generateKey: async (algorithmIdentifier: AesAlgorithm, size: number): Promise<AesKey> => {
    return await ExpoKryptomModule.generateKeyAes(algorithmIdentifier,size);
  },
  encrypt: async (data: Uint8Array, key: AesKey, iv: Uint8Array | null): Promise<Uint8Array> => {
    return await ExpoKryptomModule.encryptAes(data, (key as NativeAesKey).rawKey, key.algorithmIdentifier, iv);
  },
  decrypt: async (ivAndEncryptedData: Uint8Array, key: AesKey): Promise<Uint8Array> => {
    return await ExpoKryptomModule.decryptAes(ivAndEncryptedData, (key as NativeAesKey).rawKey, key.algorithmIdentifier);
  },
  exportRawKey: async (key: AesKey): Promise<Uint8Array> => {
    return (key as NativeAesKey).rawKey;
  },
  importRawKey: async (rawKey: Uint8Array, algorithmIdentifier: AesAlgorithm): Promise<AesKey> => {
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeAesKey = {
      rawKey,
      algorithmIdentifier
    }
    return res;
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
    if (rsaKeyNeedsExport) {
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
    if (rsaKeyNeedsExport) {
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
    if (rsaKeyNeedsExport) {
      return await ExpoKryptomModule.importPrivateKeyPkcs8Rsa(privateKeyPkcs8, algorithmIdentifier);
    }
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
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
    if (rsaKeyNeedsExport) {
      return await ExpoKryptomModule.importPublicKeySpkiRsa(publicKeySpki, algorithmIdentifier);
    }
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
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
  generateKey: async (algorithmIdentifier: HmacAlgorithm): Promise<HmacKey> => {
    return await ExpoKryptomModule.generateKeyHmac(algorithmIdentifier)
  },
  sign: async (data: Uint8Array, key: HmacKey): Promise<Uint8Array> => {
    return await ExpoKryptomModule.signHmac(key.algorithmIdentifier, (key as NativeHmacKey).rawKey, data)
  },
  verify: async (signature: Uint8Array, data: Uint8Array, key: HmacKey): Promise<boolean> => {
    return await ExpoKryptomModule.verifyHmac(key.algorithmIdentifier, (key as NativeHmacKey).rawKey, signature, data)
  },
  exportRawKey: async (key: HmacKey): Promise<Uint8Array> => {
    return (key as NativeHmacKey).rawKey;
  },
  importRawKey: async (rawKey: Uint8Array, algorithmIdentifier: HmacAlgorithm): Promise<HmacKey> => {
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeHmacKey = {
      rawKey,
      algorithmIdentifier
    }
    return res;
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

export type AesAlgorithm = "AesCbcPkcs7";
export type RsaEncryptionAlgorithm = "OaepWithSha1" | "OaepWithSha256";
export type RsaSignatureAlgorithm = "PssWithSha256";
export type RsaAlgorithm = RsaEncryptionAlgorithm | RsaSignatureAlgorithm
export type HmacAlgorithm = "HmacSha512"

export interface HmacKey {
  algorithmIdentifier: HmacAlgorithm;
};

export interface AesKey {
  algorithmIdentifier: AesAlgorithm;
}

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

type NativeRsaKeyPair = {
  public: Uint8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in SPKI format
  private: Uint8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in PKCS8 format
  algorithmIdentifier: RsaAlgorithm;
};

type NativeRsaPrivateKey = {
  private: Uint8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in SPKI format
  algorithmIdentifier: RsaAlgorithm;
};

type NativeRsaPublicKey = {
  public: Uint8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in PKCS8 format
  algorithmIdentifier: RsaAlgorithm;
};

type NativeAesKey = {
  rawKey: Uint8Array; // Representation of the key as raw bytes
  algorithmIdentifier: AesAlgorithm;
}

type NativeHmacKey = {
  rawKey: Uint8Array; // Representation of the key as raw bytes
  algorithmIdentifier: HmacAlgorithm;
}
