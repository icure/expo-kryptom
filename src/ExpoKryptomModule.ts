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
  generateKey: async (algorithmIdentifier: AesAlgorithm, size: number): Promise<AesKey> => {
    const aesKey = await ExpoKryptomModule.generateKeyAes(algorithmIdentifier,size)

    return {
        key: new Int8Array(aesKey.key),
        algorithmIdentifier: aesKey.algorithmIdentifier
    }
  },
  encrypt: async (data: Int8Array, key: AesKey, iv: Int8Array | null): Promise<Int8Array> => {
    return new Int8Array(await ExpoKryptomModule.encryptAes(new Uint8Array(data), new Uint8Array((key as NativeAesKey).key), key.algorithmIdentifier, iv ? new Uint8Array(iv) : null));
  },
  decrypt: async (ivAndEncryptedData: Int8Array, key: AesKey): Promise<Int8Array> => {
    return new Int8Array(await ExpoKryptomModule.decryptAes(new Uint8Array(ivAndEncryptedData), new Uint8Array((key as NativeAesKey).key), key.algorithmIdentifier));
  },
  exportKey: async (key: AesKey): Promise<Int8Array> => {
    return new Int8Array(await ExpoKryptomModule.exportKeyAes(new Uint8Array(key.key as Int8Array), key.algorithmIdentifier));
  },
  loadKey: async (rawKey: Int8Array, algorithmIdentifier: AesAlgorithm): Promise<AesKey> => {
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeAesKey = {
      key: rawKey,
      algorithmIdentifier
    }
    return res;
  },
};

export const Rsa: RsaService = {
  generateKey: async (algorithmIdentifier: string, size: number) => {
    return await ExpoKryptomModule.generateKeyRsa(algorithmIdentifier, size) as RsaKeyPair;
  },
  encrypt: async (data: Int8Array, key: RsaPublicKey) => {
    return new Int8Array(
        await ExpoKryptomModule.encryptRsa(
            new Uint8Array(data),
            new Uint8Array((key as NativeRsaPublicKey).publicKey),
            key.algorithmIdentifier
        )
    );
  },
  decrypt: async (data: Int8Array, key: RsaPrivateKey) => {
    return new Int8Array(
        await ExpoKryptomModule.decryptRsa(
            new Uint8Array(data),
            new Uint8Array((key as NativeRsaPrivateKey).privateKey),
            key.algorithmIdentifier
        )
    );
  },
  exportPrivateKeyPkcs8: async (key: RsaPrivateKey) => {
    if (rsaKeyNeedsExport) {
      return new Int8Array(
          await ExpoKryptomModule.exportPrivateKeyPkcs8Rsa(
              new Uint8Array((key as NativeRsaPrivateKey).privateKey),
              key.algorithmIdentifier
          )
      );
    }
    return (key as NativeRsaPrivateKey).privateKey;
  },
  exportPrivateKeyJwk: async (key: RsaPrivateKey) => {
    return await ExpoKryptomModule.exportPrivateKeyJwkRsa(
      new Uint8Array((key as NativeRsaPrivateKey).privateKey),
      key.algorithmIdentifier
    ) as PrivateRsaKeyJwk;
  },
  exportPublicKeySpki: async (key: RsaPublicKey) => {
    if (rsaKeyNeedsExport) {
      return new Int8Array(
          await ExpoKryptomModule.exportPublicKeySpkiRsa(
              new Uint8Array((key as NativeRsaPublicKey).publicKey),
              key.algorithmIdentifier
          )
      );
    }
    return (key as NativeRsaPublicKey).publicKey;
  },
  exportPublicKeyJwk: async (key: RsaPublicKey) => {
    return await ExpoKryptomModule.exportPublicKeyJwkRsa(
      new Uint8Array((key as NativeRsaPublicKey).publicKey),
      key.algorithmIdentifier
    ) as PublicRsaKeyJwk;
  },
  importPrivateKeyPkcs8: async (privateKeyPkcs8: Int8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaPrivateKey> => {
    if (rsaKeyNeedsExport) {
      const privateKey = await ExpoKryptomModule.importPrivateKeyPkcs8Rsa(new Uint8Array(privateKeyPkcs8), algorithmIdentifier)
      return {
        privateKey: new Int8Array(privateKey.privateKey),
        algorithmIdentifier: privateKey.algorithmIdentifier
      } satisfies RsaPrivateKey;
    }
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeRsaPrivateKey = {
      privateKey: privateKeyPkcs8,
      algorithmIdentifier
    }
    return res;
  },
  importPrivateKeyJwk: async (privateKey: PrivateRsaKeyJwk, algorithmIdentifier: RsaAlgorithm) => {
    const importedPrivateKey = await ExpoKryptomModule.importPrivateKeyJwkRsa(privateKey, algorithmIdentifier)
    return {
      privateKey: new Int8Array(importedPrivateKey.privateKey),
      algorithmIdentifier: importedPrivateKey.algorithmIdentifier
    } satisfies RsaPrivateKey;
  },
  importPublicKeySpki: async (publicKeySpki: Int8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaPublicKey> => {
    if (rsaKeyNeedsExport) {
      const publicKey = await ExpoKryptomModule.importPublicKeySpkiRsa(new Uint8Array(publicKeySpki), algorithmIdentifier)
      console.log(publicKey)
      return {
        publicKey: new Int8Array(publicKey.publicKey),
        algorithmIdentifier: publicKey.algorithmIdentifier
      } satisfies NativeRsaPublicKey
    }
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeRsaPublicKey = {
      publicKey: publicKeySpki,
      algorithmIdentifier
    }
    return res;
  },
  importPublicKeyJwk: async (publicKey: PublicRsaKeyJwk, algorithmIdentifier: RsaAlgorithm): Promise<RsaPublicKey> => {
    const importedPublicKey = await ExpoKryptomModule.importPublicKeyJwkRsa(publicKey, algorithmIdentifier);
    return {
        publicKey: new Int8Array(importedPublicKey.publicKey),
        algorithmIdentifier: importedPublicKey.algorithmIdentifier
      } satisfies NativeRsaPublicKey;
  },
  importKeyPair: async (privateKeyPkcs8: Int8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaKeyPair> => {
    const importedKeyPair = await ExpoKryptomModule.importKeyPairRsa(new Uint8Array(privateKeyPkcs8), algorithmIdentifier);
    return {
      publicKey: new Int8Array(importedKeyPair.publicKey),
        privateKey: new Int8Array(importedKeyPair.privateKey),
        algorithmIdentifier: importedKeyPair.algorithmIdentifier
    } satisfies NativeRsaKeyPair;
  },
  signature: async (data: Int8Array, key: RsaPrivateKey): Promise<Int8Array> => {
    return new Int8Array(await ExpoKryptomModule.signatureRsa(new Uint8Array(data), new Uint8Array((key as NativeRsaPrivateKey).privateKey), key.algorithmIdentifier));
  },
  verify: async (signature: Int8Array, data: Int8Array, key: RsaPublicKey): Promise<boolean> => {
    return await ExpoKryptomModule.verifyRsa(new Uint8Array(signature), new Uint8Array(data), new Uint8Array((key as NativeRsaPublicKey).publicKey), key.algorithmIdentifier);
  },
};

export const Hmac: HmacService = {
  generateKey: async (algorithmIdentifier: HmacAlgorithm): Promise<HmacKey> => {
    const hmacKey = await ExpoKryptomModule.generateKeyHmac(algorithmIdentifier)
    return {
        key: new Int8Array(hmacKey.key),
        algorithmIdentifier: hmacKey.algorithmIdentifier
    }
  },
  sign: async (data: Int8Array, key: HmacKey): Promise<Int8Array> => {
    return new Int8Array(await ExpoKryptomModule.signHmac(key.algorithmIdentifier, new Uint8Array((key as NativeHmacKey).key), new Uint8Array(data)));
  },
  verify: async (signature: Int8Array, data: Int8Array, key: HmacKey): Promise<boolean> => {
    return await ExpoKryptomModule.verifyHmac(key.algorithmIdentifier, new Uint8Array((key as NativeHmacKey).key), new Uint8Array(signature), new Uint8Array(data))
  },
  exportKey: async (key: HmacKey): Promise<Int8Array> => {
    return (key as NativeHmacKey).key;
  },
  loadKey: async (rawKey: Int8Array, algorithmIdentifier: HmacAlgorithm): Promise<HmacKey> => {
    // TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
    const res: NativeHmacKey = {
      key: rawKey,
      algorithmIdentifier
    }
    return res;
  },
}

export const StrongRandom : StrongRandomService = {
  randomBytes: (length: number) => {
    return new Int8Array(ExpoKryptomModule.randomBytes(length));
  },
  randomUUID: () => {
    return ExpoKryptomModule.randomUUID() as string;
  },
}

export const Digest : DigestService = {
  sha256: async (data: Int8Array) => {
    return new Int8Array(await ExpoKryptomModule.sha256(new Uint8Array(data)))
  },
}

interface NativeRsaKeyPair extends RsaKeyPair {
  publicKey: Int8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in SPKI format
  privateKey: Int8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in PKCS8 format
}

interface NativeRsaPrivateKey extends RsaPrivateKey {
  privateKey: Int8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in SPKI format
}

interface NativeRsaPublicKey extends RsaPublicKey {
  publicKey: Int8Array; // If `rsaKeyNeedsExport` is true, this is the public key in some implementation-dependent format, if false this is the key in PKCS8 format
}

interface NativeAesKey extends AesKey {
  key: Int8Array; // Representation of the key as raw bytes
}

interface NativeHmacKey extends HmacKey {
  key: Int8Array; // Representation of the key as raw bytes
}
