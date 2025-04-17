export enum AesAlgorithm {
	AesCbcPkcs7 = "AesCbcPkcs7"
}

export enum RsaEncryptionAlgorithm {
	OaepWithSha1 = "OaepWithSha1",
	OaepWithSha256 = "OaepWithSha256"
}

export enum RsaSignatureAlgorithm {
	PssWithSha256 = "PssWithSha256"
}

export type RsaAlgorithm = RsaEncryptionAlgorithm | RsaSignatureAlgorithm

export enum HmacAlgorithm {
	HmacSha512 = "HmacSha512",
	HmacSha256 = "HmacSha256"
}

export interface HmacKey {
	readonly algorithm: HmacAlgorithm;
	readonly keySize: number;
	readonly hmacKey?: unknown; // Actual type and format depends on the platform
};

export interface AesKey {
	algorithm: AesAlgorithm;
	aesKey: unknown; // Actual type and format depends on the platform
}

export interface RsaKeyPair {
	private: RsaPrivateKey;
	public: RsaPublicKey;
}

export interface RsaPrivateKey {
	algorithm: RsaAlgorithm
	privateKey: unknown; // Actual type and format depends on the platform
}

export interface RsaPublicKey {
	algorithm: RsaAlgorithm
	publicKey: unknown; // Actual type and format depends on the platform
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

export interface AesService {
	generateKey(algorithm: AesAlgorithm, keySize: number): Promise<AesKey>

	encrypt(data: Uint8Array, key: AesKey, iv?: Uint8Array): Promise<Uint8Array>

	decrypt(ivAndEncryptedData: Uint8Array, key: AesKey): Promise<Uint8Array>

	exportKey(key: AesKey): Promise<Uint8Array>

	loadKey(algorithm: AesAlgorithm, rawKey: Uint8Array): Promise<AesKey>
}

export interface RsaService {
	generateKeyPair(algorithm: RsaAlgorithm, keySize: number): Promise<RsaKeyPair>

	exportPrivateKeyPkcs8(key: RsaPrivateKey): Promise<Uint8Array>

	exportPublicKeySpki(key: RsaPublicKey): Promise<Uint8Array>

	loadKeyPairPkcs8(algorithm: RsaAlgorithm, privateKeyPkcs8: Uint8Array): Promise<RsaKeyPair>

	loadPrivateKeyPkcs8(algorithm: RsaAlgorithm, privateKeyPkcs8: Uint8Array): Promise<RsaPrivateKey>

	loadPublicKeySpki(algorithm: RsaAlgorithm, publicKeySpki: Uint8Array): Promise<RsaPublicKey>

	encrypt(data: Uint8Array, key: RsaPublicKey): Promise<Uint8Array>

	decrypt(data: Uint8Array, key: RsaPrivateKey): Promise<Uint8Array>

	sign(data: Uint8Array, key: RsaPrivateKey): Promise<Uint8Array>

	verifySignature(signature: Uint8Array, data: Uint8Array, key: RsaPublicKey): Promise<boolean>

	exportPrivateKeyJwk(key: RsaPrivateKey): Promise<PrivateRsaKeyJwk>

	exportPublicKeyJwk(key: RsaPublicKey): Promise<PublicRsaKeyJwk>

	loadPrivateKeyJwk(privateKeyJwk: PrivateRsaKeyJwk): Promise<RsaPrivateKey>

	loadPublicKeyJwk(publicKeyJwk: PublicRsaKeyJwk): Promise<RsaPublicKey>
}

export interface HmacService {
	generateKey(algorithm: HmacAlgorithm, keySize?: number): Promise<HmacKey>

	exportKey(key: HmacKey): Promise<Uint8Array>

	loadKey(algorithm: HmacAlgorithm, bytes: Uint8Array): Promise<HmacKey>

	sign(data: Uint8Array, key: HmacKey): Promise<Uint8Array>

	verify(signature: Uint8Array, data: Uint8Array, key: HmacKey): Promise<boolean>
}

export interface StrongRandomService {
	randomBytes(length: number): Uint8Array

	randomUUID(): string
}

export interface DigestService {
	sha256(data: Uint8Array): Promise<Uint8Array>

	sha512(data: Uint8Array): Promise<Uint8Array>
}
