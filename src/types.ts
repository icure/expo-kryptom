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
  HmacSha512 = "HmacSha512"
}

export interface HmacKey {
  algorithmIdentifier: HmacAlgorithm;
  key: unknown; // Actual type and format depends on the platform
};

export interface AesKey {
  algorithmIdentifier: AesAlgorithm;
  key: unknown; // Actual type and format depends on the platform
}

export interface RsaKeyPair {
  algorithmIdentifier: RsaAlgorithm
  privateKey: unknown; // Actual type and format depends on the platform
  publicKey: unknown; // Actual type and format depends on the platform
}

export interface RsaPrivateKey {
  algorithmIdentifier: RsaAlgorithm
  privateKey: unknown; // Actual type and format depends on the platform
}

export interface RsaPublicKey {
  algorithmIdentifier: RsaAlgorithm
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
  generateKey(algorithmIdentifier: AesAlgorithm, size: number): Promise<AesKey>
  encrypt(data: Int8Array, key: AesKey, iv: Int8Array | null): Promise<Int8Array>
  decrypt(ivAndEncryptedData: Int8Array, key: AesKey): Promise<Int8Array>
  exportKey(key: AesKey): Promise<Int8Array>
  loadKey(rawKey: Int8Array, algorithmIdentifier: AesAlgorithm): Promise<AesKey>
}

export interface RsaService {
  generateKey(algorithmIdentifier: RsaAlgorithm, size: number): Promise<RsaKeyPair>
  encrypt(data: Int8Array, key: RsaPublicKey): Promise<Int8Array>
  decrypt(data: Int8Array, key: RsaPrivateKey): Promise<Int8Array>
  signature(data: Int8Array, key: RsaPrivateKey): Promise<Int8Array>
  verify(signature: Int8Array, data: Int8Array, key: RsaPublicKey): Promise<boolean>
  exportPrivateKeyPkcs8(key: RsaPrivateKey): Promise<Int8Array>
  exportPrivateKeyJwk(key: RsaPrivateKey): Promise<PrivateRsaKeyJwk>
  exportPublicKeySpki(key: RsaPublicKey): Promise<Int8Array>
  exportPublicKeyJwk(key: RsaPublicKey): Promise<PublicRsaKeyJwk>
  importPrivateKeyPkcs8(privateKeyPkcs8: Int8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaPrivateKey>
  importPrivateKeyJwk(privateKey: PrivateRsaKeyJwk, algorithmIdentifier: RsaAlgorithm): Promise<RsaPrivateKey>
  importPublicKeySpki(publicKeySpki: Int8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaPublicKey>
  importPublicKeyJwk(publicKey: PublicRsaKeyJwk, algorithmIdentifier: RsaAlgorithm): Promise<RsaPublicKey>
  importKeyPair(privateKeyPkcs8: Int8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaKeyPair>
};

export interface HmacService {
  generateKey(algorithmIdentifier: HmacAlgorithm): Promise<HmacKey>
  sign(data: Int8Array, key: HmacKey): Promise<Int8Array>
  verify(signature: Int8Array, data: Int8Array, key: HmacKey): Promise<boolean>
  exportKey(key: HmacKey): Promise<Int8Array>
  loadKey(rawKey: Int8Array, algorithmIdentifier: HmacAlgorithm): Promise<HmacKey>
}

export interface StrongRandomService {
  randomBytes(length: number): Int8Array
  randomUUID(): string
}

export interface DigestService {
  sha256(data: Int8Array): Promise<Int8Array>
}
