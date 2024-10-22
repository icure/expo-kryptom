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
  algorithm: HmacAlgorithm;
  key: unknown; // Actual type and format depends on the platform
};

export interface AesKey {
  algorithm: AesAlgorithm;
  key: unknown; // Actual type and format depends on the platform
}

export interface RsaKeyPair {
  algorithm: RsaAlgorithm
  privateKey: unknown; // Actual type and format depends on the platform
  publicKey: unknown; // Actual type and format depends on the platform
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
  encrypt(data: Int8Array, key: AesKey, iv?: Int8Array): Promise<Int8Array>
  decrypt(ivAndEncryptedData: Int8Array, key: AesKey): Promise<Int8Array>
  exportKey(key: AesKey): Promise<Int8Array>
  loadKey(algorithm: AesAlgorithm, rawKey: Int8Array): Promise<AesKey>
}

export interface RsaService {
  generateKeyPair(algorithm: RsaAlgorithm, keySize: number): Promise<RsaKeyPair>
  exportPrivateKeyPkcs8(key: RsaPrivateKey): Promise<Int8Array>
  exportPublicKeySpki(key: RsaPublicKey): Promise<Int8Array>
  loadKeyPairPkcs8(algorithm: RsaAlgorithm, privateKeyPkcs8: Int8Array): Promise<RsaKeyPair>
  loadPrivateKeyPkcs8(algorithm: RsaAlgorithm, privateKeyPkcs8: Int8Array): Promise<RsaPrivateKey>
  loadPublicKeySpki(algorithm: RsaAlgorithm, publicKeySpki: Int8Array): Promise<RsaPublicKey>
  encrypt(data: Int8Array, key: RsaPublicKey): Promise<Int8Array>
  decrypt(data: Int8Array, key: RsaPrivateKey): Promise<Int8Array>
  sign(data: Int8Array, key: RsaPrivateKey): Promise<Int8Array>
  verifySignature(signature: Int8Array, data: Int8Array, key: RsaPublicKey): Promise<boolean>
  exportPrivateKeyJwk(key: RsaPrivateKey): Promise<PrivateRsaKeyJwk>
  exportPublicKeyJwk(key: RsaPublicKey): Promise<PublicRsaKeyJwk>
  loadPrivateKeyJwk(privateKeyJwk: PrivateRsaKeyJwk): Promise<RsaPrivateKey>
  loadPublicKeyJwk(publicKeyJwk: PublicRsaKeyJwk): Promise<RsaPublicKey>
}

export interface HmacService {
  generateKey(algorithm: HmacAlgorithm, keySize?: number): Promise<HmacKey>
  exportKey(key: HmacKey): Promise<Int8Array>
  loadKey(algorithm: HmacAlgorithm, bytes: Int8Array): Promise<HmacKey>
  sign(data: Int8Array, key: HmacKey): Promise<Int8Array>
  verify(signature: Int8Array, data: Int8Array, key: HmacKey): Promise<boolean>
}

export interface StrongRandomService {
  randomBytes(length: number): Int8Array
  randomUUID(): string
}

export interface DigestService {
  sha256(data: Int8Array): Promise<Int8Array>
}
