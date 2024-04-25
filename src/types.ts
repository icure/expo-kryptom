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

export interface AesService {
  generateKey(algorithmIdentifier: AesAlgorithm, size: number): Promise<AesKey>
  encrypt(data: Uint8Array, key: AesKey, iv: Uint8Array | null): Promise<Uint8Array>
  decrypt(ivAndEncryptedData: Uint8Array, key: AesKey): Promise<Uint8Array>
  exportRawKey(key: AesKey): Promise<Uint8Array>
  importRawKey(rawKey: Uint8Array, algorithmIdentifier: AesAlgorithm): Promise<AesKey>
}

export interface RsaService {
  generateKey(algorithmIdentifier: RsaAlgorithm, size: number): Promise<RsaKeyPair>
  encrypt(data: Uint8Array, key: RsaPublicKey): Promise<Uint8Array>
  decrypt(data: Uint8Array, key: RsaPrivateKey): Promise<Uint8Array>
  signature(data: Uint8Array, key: RsaPrivateKey): Promise<Uint8Array>
  verify(signature: Uint8Array, data: Uint8Array, key: RsaPublicKey): Promise<boolean>
  exportPrivateKeyPkcs8(key: RsaPrivateKey): Promise<Uint8Array>
  exportPrivateKeyJwk(key: RsaPrivateKey): Promise<PrivateRsaKeyJwk>
  exportPublicKeySpki(key: RsaPublicKey): Promise<Uint8Array>
  exportPublicKeyJwk(key: RsaPublicKey): Promise<PublicRsaKeyJwk>
  importPrivateKeyPkcs8(privateKeyPkcs8: Uint8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaPrivateKey>
  importPrivateKeyJwk(privateKey: PrivateRsaKeyJwk, algorithmIdentifier: RsaAlgorithm): Promise<RsaPrivateKey>
  importPublicKeySpki(publicKeySpki: Uint8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaPublicKey>
  importPublicKeyJwk(publicKey: PublicRsaKeyJwk, algorithmIdentifier: RsaAlgorithm): Promise<RsaPublicKey>
  importKeyPair(privateKeyPkcs8: Uint8Array, algorithmIdentifier: RsaAlgorithm): Promise<RsaKeyPair>
};

export interface HmacService {
  generateKey(algorithmIdentifier: HmacAlgorithm): Promise<HmacKey>
  sign(data: Uint8Array, key: HmacKey): Promise<Uint8Array>
  verify(signature: Uint8Array, data: Uint8Array, key: HmacKey): Promise<boolean>
  exportRawKey(key: HmacKey): Promise<Uint8Array>
  importRawKey(rawKey: Uint8Array, algorithmIdentifier: HmacAlgorithm): Promise<HmacKey>
}

export interface StrongRandomService {
  randomBytes(length: number): Uint8Array
  randomUUID(): string
}

export interface DigestService {
  sha256(data: Uint8Array): Promise<Uint8Array>
}
