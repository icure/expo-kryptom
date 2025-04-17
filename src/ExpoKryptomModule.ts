import { requireNativeModule } from "expo-modules-core";
import {
	AesAlgorithm,
	AesKey,
	AesService,
	DigestService,
	HmacAlgorithm,
	HmacKey,
	HmacService,
	PrivateRsaKeyJwk,
	PublicRsaKeyJwk,
	RsaAlgorithm,
	RsaKeyPair,
	RsaPrivateKey,
	RsaPublicKey,
	RsaService,
	StrongRandomService
} from './types'

// It loads the native module object from the JSI or falls back to
// the bridge module (from NativeModulesProxy) if the remote debugger is on.
const ExpoKryptomModule = requireNativeModule("ExpoKryptom");

const rsaKeyNeedsExport = ExpoKryptomModule.rsaKeyNeedsExport;

export const Aes: AesService = {
	generateKey: async (algorithm: AesAlgorithm, size: number): Promise<AesKey> => {
		const aesKey = await ExpoKryptomModule.generateKeyAes(algorithm, size)
		return {
			aesKey: new Uint8Array(aesKey.aesKey),
			algorithm: aesKey.algorithm
		}
	},
	encrypt: async (data: Uint8Array, key: AesKey, iv?: Uint8Array): Promise<Uint8Array> => {
		return await ExpoKryptomModule.encryptAes(new Uint8Array(data), new Uint8Array((key as NativeAesKey).aesKey), key.algorithm, iv ? new Uint8Array(iv) : null);
	},
	decrypt: async (ivAndEncryptedData: Uint8Array, key: AesKey): Promise<Uint8Array> => {
		return await ExpoKryptomModule.decryptAes(new Uint8Array(ivAndEncryptedData), new Uint8Array((key as NativeAesKey).aesKey), key.algorithm);
	},
	exportKey: async (key: AesKey): Promise<Uint8Array> => {
		return await ExpoKryptomModule.exportKeyAes(new Uint8Array(key.aesKey as Uint8Array), key.algorithm);
	},
	loadKey: async (algorithm: AesAlgorithm, rawKey: Uint8Array): Promise<AesKey> => {
		// TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
		const res: NativeAesKey = {
			aesKey: new Uint8Array(rawKey),
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
				privateKey: new Uint8Array(keyPair.private.privateKey),
				algorithm: keyPair.private.algorithm
			},
			public: {
				publicKey: new Uint8Array(keyPair.public.publicKey),
				algorithm: keyPair.public.algorithm
			}
		} satisfies NativeRsaKeyPair;
	},
	encrypt: async (data: Uint8Array, key: RsaPublicKey) => {
		return await ExpoKryptomModule.encryptRsa(
			new Uint8Array(data),
			new Uint8Array((key as NativeRsaPublicKey).publicKey),
			key.algorithm
		);
	},
	decrypt: async (data: Uint8Array, key: RsaPrivateKey) => {
		return await ExpoKryptomModule.decryptRsa(
			new Uint8Array(data),
			new Uint8Array((key as NativeRsaPrivateKey).privateKey),
			key.algorithm
		);
	},
	exportPrivateKeyPkcs8: async (key: RsaPrivateKey) => {
		if (rsaKeyNeedsExport) {
			return await ExpoKryptomModule.exportPrivateKeyPkcs8Rsa(
				new Uint8Array((key as NativeRsaPrivateKey).privateKey),
				key.algorithm
			);
		}
		return new Uint8Array((key as NativeRsaPrivateKey).privateKey);
	},
	exportPrivateKeyJwk: async (key: RsaPrivateKey) => {
		return await ExpoKryptomModule.exportPrivateKeyJwkRsa(
			new Uint8Array((key as NativeRsaPrivateKey).privateKey),
			key.algorithm
		) as PrivateRsaKeyJwk;
	},
	exportPublicKeySpki: async (key: RsaPublicKey) => {
		if (rsaKeyNeedsExport) {
			return await ExpoKryptomModule.exportPublicKeySpkiRsa(
				new Uint8Array((key as NativeRsaPublicKey).publicKey),
				key.algorithm
			);
		}
		return new Uint8Array((key as NativeRsaPublicKey).publicKey);
	},
	exportPublicKeyJwk: async (key: RsaPublicKey) => {
		return await ExpoKryptomModule.exportPublicKeyJwkRsa(
			new Uint8Array((key as NativeRsaPublicKey).publicKey),
			key.algorithm
		) as PublicRsaKeyJwk;
	},
	loadPrivateKeyPkcs8: async (algorithm: RsaAlgorithm, privateKeyPkcs8: Uint8Array): Promise<RsaPrivateKey> => {
		if (rsaKeyNeedsExport) {
			const privateKey = await ExpoKryptomModule.importPrivateKeyPkcs8Rsa(new Uint8Array(privateKeyPkcs8), algorithm)
			return {
				privateKey: new Uint8Array(privateKey.privateKey),
				algorithm: privateKey.algorithm
			} satisfies RsaPrivateKey;
		}
		// TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
		const res: NativeRsaPrivateKey = {
			privateKey: new Uint8Array(privateKeyPkcs8),
			algorithm: algorithm
		}
		return res;
	},
	loadPrivateKeyJwk: async (privateKey: PrivateRsaKeyJwk) => {
		const importedPrivateKey = await ExpoKryptomModule.importPrivateKeyJwkRsa(privateKey)
		return {
			privateKey: new Uint8Array(importedPrivateKey.privateKey),
			algorithm: importedPrivateKey.algorithm
		} satisfies RsaPrivateKey;
	},
	loadPublicKeySpki: async (algorithm: RsaAlgorithm, publicKeySpki: Uint8Array): Promise<RsaPublicKey> => {
		if (rsaKeyNeedsExport) {
			const publicKey = await ExpoKryptomModule.importPublicKeySpkiRsa(new Uint8Array(publicKeySpki), algorithm)
			return {
				publicKey: new Uint8Array(publicKey.publicKey),
				algorithm: publicKey.algorithm
			} satisfies NativeRsaPublicKey
		}
		// TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
		const res: NativeRsaPublicKey = {
			publicKey: new Uint8Array(publicKeySpki),
			algorithm: algorithm
		}
		return res;
	},
	loadPublicKeyJwk: async (publicKey: PublicRsaKeyJwk): Promise<RsaPublicKey> => {
		const importedPublicKey = await ExpoKryptomModule.importPublicKeyJwkRsa(publicKey);
		return {
			publicKey: new Uint8Array(importedPublicKey.publicKey),
			algorithm: importedPublicKey.algorithm
		} satisfies NativeRsaPublicKey;
	},
	loadKeyPairPkcs8: async (algorithm: RsaAlgorithm, privateKeyPkcs8: Uint8Array): Promise<RsaKeyPair> => {
		const importedKeyPair = await ExpoKryptomModule.importKeyPairRsa(new Uint8Array(privateKeyPkcs8), algorithm);
		return {
			public: {
				publicKey: new Uint8Array(importedKeyPair.public.publicKey),
				algorithm: importedKeyPair.public.algorithm
			},
			private: {
				privateKey: new Uint8Array(importedKeyPair.private.privateKey),
				algorithm: importedKeyPair.private.algorithm
			},
		} satisfies NativeRsaKeyPair;
	},
	sign: async (data: Uint8Array, key: RsaPrivateKey): Promise<Uint8Array> => {
		return await ExpoKryptomModule.signatureRsa(new Uint8Array(data), new Uint8Array((key as NativeRsaPrivateKey).privateKey), key.algorithm);
	},
	verifySignature: async (signature: Uint8Array, data: Uint8Array, key: RsaPublicKey): Promise<boolean> => {
		return await ExpoKryptomModule.verifyRsa(new Uint8Array(signature), new Uint8Array(data), new Uint8Array((key as NativeRsaPublicKey).publicKey), key.algorithm);
	},
};

export const Hmac: HmacService = {
	generateKey: async (algorithmIdentifier: HmacAlgorithm): Promise<HmacKey> => {
		const hmacKey = await ExpoKryptomModule.generateKeyHmac(algorithmIdentifier)
		return {
			hmacKey: new Uint8Array(hmacKey.hmacKey),
			algorithm: hmacKey.algorithm,
			keySize: hmacKey.keySize
		}
	},
	sign: async (data: Uint8Array, key: HmacKey): Promise<Uint8Array> => {
		return await ExpoKryptomModule.signHmac(key.algorithm, new Uint8Array((key as NativeHmacKey).hmacKey), new Uint8Array(data));
	},
	verify: async (signature: Uint8Array, data: Uint8Array, key: HmacKey): Promise<boolean> => {
		return await ExpoKryptomModule.verifyHmac(key.algorithm, new Uint8Array((key as NativeHmacKey).hmacKey), new Uint8Array(signature), new Uint8Array(data))
	},
	exportKey: async (key: HmacKey): Promise<Uint8Array> => {
		return new Uint8Array((key as NativeHmacKey).hmacKey);
	},
	loadKey: async (algorithm: HmacAlgorithm, bytes: Uint8Array): Promise<HmacKey> => {
		// TODO: note that if algorithm is invalid the user will get an error only when first using the key to encrypt/decrypt
		const res: NativeHmacKey = {
			hmacKey: new Uint8Array(bytes),
			algorithm,
			keySize: bytes.length
		}
		return res;
	},
}

export const StrongRandom: StrongRandomService = {
	randomBytes: (length: number) => {
		return ExpoKryptomModule.randomBytes(length);
	},
	randomUUID: () => {
		return ExpoKryptomModule.randomUUID() as string;
	},
}

export const Digest: DigestService = {
	sha256: async (data: Uint8Array) => {
		return await ExpoKryptomModule.sha256(new Uint8Array(data.buffer));
	},
	sha512: async (data: Uint8Array) => {
		return await ExpoKryptomModule.sha512(new Uint8Array(data.buffer));
	}
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
