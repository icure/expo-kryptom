// Import the native module. On web, it will be resolved to ExpoKryptom.web.ts

import { StrongRandom } from './ExpoKryptomModule';

// and on native platforms to ExpoKryptom.ts
export { 
  AesAlgorithm, 
  AesKey, 
  RsaKeyPair, 
  RsaPublicKey, 
  RsaPrivateKey, 
  PrivateRsaKeyJwk, 
  PublicRsaKeyJwk, 
  RsaAlgorithm, 
  RsaSignatureAlgorithm,
  RsaEncryptionAlgorithm,
  HmacAlgorithm, 
  HmacKey
} from './types'
export {
  Aes,
  Rsa,
  Hmac,
  StrongRandom,
  Digest
} from './ExpoKryptomModule'

if (window.crypto === undefined) {
  // noinspection JSConstantReassignment
  window.crypto = {
    getRandomValues: (array: Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | BigInt64Array | BigUint64Array) => {
      const randomBytes: Uint8Array = StrongRandom.randomBytes(array.byteLength);
      const toSet = new Uint8Array(array.buffer);
      toSet.set(randomBytes);
      return array;
    },
    getRandomUUID: () => {
      return StrongRandom.randomUUID()
    }
  } as any
}