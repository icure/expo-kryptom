// @ts-ignore
import {polyfillGlobal} from 'react-native/Libraries/Utilities/PolyfillFunctions';
import {StrongRandom} from './ExpoKryptomModule';

const strongRandomCrypto = {
	getRandomValues: (array: Int8Array | Uint8Array | Uint8ClampedArray | Int16Array | Uint16Array | Int32Array | Uint32Array | BigInt64Array | BigUint64Array) => {
		const randomBytes: Uint8Array = StrongRandom.randomBytes(array.byteLength);
		const toSet = new Uint8Array(array.buffer);
		toSet.set(randomBytes);
		return array;
	},
	randomUUID: () => {
		return StrongRandom.randomUUID()
	}
} as Crypto

/**
 * Provides a partial implementation of the web crypto api through `window.crypto`.
 * The implementation supports `getRandomValues` and `randomUUID` through Kryptom's StrongRandom service.
 * No other methods are supported.
 */
export function polyfillWindowCryptoWithStrongRandom() {
	(window as any).crypto = strongRandomCrypto;
}

/**
 * Provides a partial implementation of the web crypto api through a global `crypto` object.
 * The implementation supports `getRandomValues` and `randomUUID` through Kryptom's StrongRandom service.
 * No other methods are supported.
 */
export function polyfillGlobalCryptoWithStrongRandom() {
	polyfillGlobal('crypto', () => strongRandomCrypto);
}