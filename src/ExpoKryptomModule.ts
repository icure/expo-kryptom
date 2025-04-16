import { requireNativeModule } from "expo-modules-core";
import { 
  AesAlgorithm, 
  AesKey, 
  RsaKeyPair, 
  RsaPublicKey, 
  RsaPrivateKey, 
  PrivateRsaKeyJwk, 
  PublicRsaKeyJwk, 
  RsaAlgorithm, 
  HmacAlgorithm, 
  HmacKey,
  AesService,
  RsaService,
  HmacService,
  StrongRandomService,
  DigestService
} from './types'

// It loads the native module object from the JSI or falls back to
// the bridge module (from NativeModulesProxy) if the remote debugger is on.
const ExpoKryptomModule = requireNativeModule("ExpoKryptom");

const rsaKeyNeedsExport = ExpoKryptomModule.rsaKeyNeedsExport;

export const Aes : AesService = {
  generateKey: async (algorithm: AesAlgorithm, size: number): Promise<AesKey> => {
    const aesKey = await ExpoKryptomModule.generateKeyAes(algorithm, size)
    return {
        aesKey: (aesKey.aesKey),
        algorithm: aesKey.algorithm
    }
  },
  encrypt: async (data: Uint8Array, key: AesKey, iv?: Uint8Array): Promise<Uint8Array> => {
    return (await ExpoKryptomModule.encryptAes((data), ((key as NativeAesKey).aesKey), key.algorithm, iv ? (iv) : null));
  },
  decrypt: async (ivAndEncryptedData: Uint8Array, key: AesKey): Promise<Uint8Array> => {
    return (await ExpoKryptomModule.decryptAes((ivAndEncryptedData), ((key as NativeAesKey).aesKey), key.algorithm));
  },
  exportKey: async (key: AesKey): Promise<Uint8Array> => {
    return (await ExpoKryptomModule.exportKeyAes(((key.aesKey as Uint8Array)), key.algorithm));
  },
  loadKey: async (algorithm: AesAlgorithm, rawKey: Uint8Array): Promise<AesKey> => {
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeAesKey = {
      aesKey: rawKey,
      algorithm: algorithm
    }
    return res;
  },
};

export const Rsa: RsaService = {
  generateKeyPair: async (algorithm: string, keySize: number) => {
    const keyPair = await ExpoKryptomModule.generateKeyRsa(algorithm, keySize);
    return {
      private: {
        privateKey: (keyPair.private.privateKey),
        algorithm: keyPair.private.algorithm
      },
      public: {
        publicKey: (keyPair.public.publicKey),
        algorithm: keyPair.public.algorithm
      }
    } satisfies NativeRsaKeyPair;
  },
  encrypt: async (data: Uint8Array, key: RsaPublicKey) => {
    return (
        await ExpoKryptomModule.encryptRsa(
            (data),
            ((key as NativeRsaPublicKey).publicKey),
            key.algorithm
        )
    );
  },
  decrypt: async (data: Uint8Array, key: RsaPrivateKey) => {
    return (
        await ExpoKryptomModule.decryptRsa(
            (data),
            ((key as NativeRsaPrivateKey).privateKey),
            key.algorithm
        )
    );
  },
  exportPrivateKeyPkcs8: async (key: RsaPrivateKey) => {
    if (rsaKeyNeedsExport) {
      return (
          await ExpoKryptomModule.exportPrivateKeyPkcs8Rsa(
              ((key as NativeRsaPrivateKey).privateKey),
              key.algorithm
          )
      );
    }
    return (key as NativeRsaPrivateKey).privateKey;
  },
  exportPrivateKeyJwk: async (key: RsaPrivateKey) => {
    return await ExpoKryptomModule.exportPrivateKeyJwkRsa(
      ((key as NativeRsaPrivateKey).privateKey),
      key.algorithm
    ) as PrivateRsaKeyJwk;
  },
  exportPublicKeySpki: async (key: RsaPublicKey) => {
    if (rsaKeyNeedsExport) {
      return (
          await ExpoKryptomModule.exportPublicKeySpkiRsa(
              ((key as NativeRsaPublicKey).publicKey),
              key.algorithm
          )
      );
    }
    return (key as NativeRsaPublicKey).publicKey;
  },
  exportPublicKeyJwk: async (key: RsaPublicKey) => {
    return await ExpoKryptomModule.exportPublicKeyJwkRsa(
      ((key as NativeRsaPublicKey).publicKey),
      key.algorithm
    ) as PublicRsaKeyJwk;
  },
  loadPrivateKeyPkcs8: async (algorithm: RsaAlgorithm, privateKeyPkcs8: Uint8Array): Promise<RsaPrivateKey> => {
    if (rsaKeyNeedsExport) {
      const privateKey = await ExpoKryptomModule.importPrivateKeyPkcs8Rsa((privateKeyPkcs8), algorithm)
      return {
        privateKey: (privateKey.privateKey),
        algorithm: privateKey.algorithm
      } satisfies RsaPrivateKey;
    }
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeRsaPrivateKey = {
      privateKey: privateKeyPkcs8,
      algorithm: algorithm
    }
    return res;
  },
  loadPrivateKeyJwk: async (privateKey: PrivateRsaKeyJwk) => {
    const importedPrivateKey = await ExpoKryptomModule.importPrivateKeyJwkRsa(privateKey)
    return {
      privateKey: (importedPrivateKey.privateKey),
      algorithm: importedPrivateKey.algorithm
    } satisfies RsaPrivateKey;
  },
  loadPublicKeySpki: async (algorithm: RsaAlgorithm, publicKeySpki: Uint8Array): Promise<RsaPublicKey> => {
    if (rsaKeyNeedsExport) {
      const publicKey = await ExpoKryptomModule.importPublicKeySpkiRsa((publicKeySpki), algorithm)
      return {
        publicKey: (publicKey.publicKey),
        algorithm: publicKey.algorithm
      } satisfies NativeRsaPublicKey
    }
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeRsaPublicKey = {
      publicKey: publicKeySpki,
      algorithm: algorithm
    }
    return res;
  },
  loadPublicKeyJwk: async (publicKey: PublicRsaKeyJwk): Promise<RsaPublicKey> => {
    const importedPublicKey = await ExpoKryptomModule.importPublicKeyJwkRsa(publicKey);
    return {
        publicKey: (importedPublicKey.publicKey),
        algorithm: importedPublicKey.algorithm
      } satisfies NativeRsaPublicKey;
  },
  loadKeyPairPkcs8: async (algorithm: RsaAlgorithm, privateKeyPkcs8: Uint8Array): Promise<RsaKeyPair> => {
    const importedKeyPair = await ExpoKryptomModule.importKeyPairRsa((privateKeyPkcs8), algorithm);
    return {
      public: {
        publicKey: (importedKeyPair.public.publicKey),
        algorithm: importedKeyPair.public.algorithm
      },
      private: {
        privateKey: (importedKeyPair.private.privateKey),
        algorithm: importedKeyPair.private.algorithm
      },
    } satisfies NativeRsaKeyPair;
  },
  sign: async (data: Uint8Array, key: RsaPrivateKey): Promise<Uint8Array> => {
    return (await ExpoKryptomModule.signatureRsa((data), ((key as NativeRsaPrivateKey).privateKey), key.algorithm));
  },
  verifySignature: async (signature: Uint8Array, data: Uint8Array, key: RsaPublicKey): Promise<boolean> => {
    return await ExpoKryptomModule.verifyRsa((signature), (data), ((key as NativeRsaPublicKey).publicKey), key.algorithm);
  },
};

export const Hmac: HmacService = {
  generateKey: async (algorithmIdentifier: HmacAlgorithm): Promise<HmacKey> => {
    const hmacKey = await ExpoKryptomModule.generateKeyHmac(algorithmIdentifier)
    return {
        hmacKey: (hmacKey.hmacKey),
        algorithm: hmacKey.algorithm,
        keySize: hmacKey.keySize
    }
  },
  sign: async (data: Uint8Array, key: HmacKey): Promise<Uint8Array> => {
    return (await ExpoKryptomModule.signHmac(key.algorithm, ((key as NativeHmacKey).hmacKey), (data)));
  },
  verify: async (signature: Uint8Array, data: Uint8Array, key: HmacKey): Promise<boolean> => {
    return await ExpoKryptomModule.verifyHmac(key.algorithm, ((key as NativeHmacKey).hmacKey), (signature), (data))
  },
  exportKey: async (key: HmacKey): Promise<Uint8Array> => {
    return (key as NativeHmacKey).hmacKey;
  },
  loadKey: async (algorithm: HmacAlgorithm, bytes: Uint8Array): Promise<HmacKey> => {
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeHmacKey = {
      hmacKey: bytes,
      algorithm,
      keySize: bytes.length
    }
    return res;
  },
}

export const StrongRandom : StrongRandomService = {
  randomBytes: (length: number) => {
    return (ExpoKryptomModule.randomBytes(length));
  },
  randomUUID: () => {
    return ExpoKryptomModule.randomUUID() as string;
  },
}

export const Digest : DigestService = {
  sha256: async (data: Uint8Array) => {
    return (await ExpoKryptomModule.sha256(new Uint8Array(data.buffer)));
  },
}

interface NativeRsaKeyPair extends RsaKeyPair {
  public: NativeRsaPublicKey;
  private: NativeRsaPrivateKey;
}

interface NativeRsaPrivateKey extends RsaPrivateKey {
  privateKey: Uint8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in SPKI format
}

interface NativeRsaPublicKey extends RsaPublicKey {
  publicKey: Uint8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in PKCS8 format
}

interface NativeAesKey extends AesKey {
  aesKey: Uint8Array; // Representation of the key as raw bytes
}

interface NativeHmacKey extends HmacKey {
  hmacKey: Uint8Array; // Representation of the key as raw bytes
}
