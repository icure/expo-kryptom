import { Aes, Hmac, Rsa } from "expo-kryptom"

const data = "The quick brown fox jumps over the lazy dog"
const dataBytes = new Uint8Array(Buffer.from(data, "utf-8"))
const aesKey = "vNImq6i5ff6Y8UhhqhyGWw=="
const aesEncryptedData = "Yfp9eibllZVoVBaznalQ8F6jQtE/BTBI9cwVAvu0ZV3TqJhbOkCf1YIW1P21Gekl5hPN5uSE9Uj5LSWT7cp83Q=="
const rsaKeyPrivate = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDRwnz+NTVzKu7mPhVqLMT6clQG/FZAkv7ATpfbGZpjsuIRj/8ZU3a9oXmIH4f0" +
    "wKbqN9lRECwmfgWxaXdjoUilDXqMUrk4onHa/EfFfzb+BPxGj1cM0wVyZiYbq68vdmI4TAZicB8BUngvX74EJFA31Df5nghjnKnqpqbHaKtw" +
    "+kiWRCE5Guz6A3BdcDc/qDmBd9vSqLryfljXMF1bZGXlzcyjegqy9jaYFi0vuQOoXOPWLnHmMU29Rdiw+8UEHqHE6DRLgGXrumSDFE68L0va" +
    "gbnh+Ea+dEQ9PNrWJShVk0xO6rjwhbEZdxqf+KYX5lMic/cR7wGHfGvi2XpQOo35AgMBAAECggEAYzSEMChTKK5oAZ3gO/CDkt2Kjyk909mR" +
    "wbsKCBZCVh/O2raLVFuMn6AknfQntWJ+Lu0OC1BGSUg2AhPa4tRvSpym1oHzVu1BQuwpN6d0h0wtUmPNrGOLQnE8Wb7nol9vkaenJ1xW1aW+" +
    "8MzrzgKsq9LjTFvpJM9971w1Kb9/wfTKNkd3jTC2oc+Ub/MVK4hCvU0/7DxMTDalTzrGKoRZQgdlFZ3FufK9Voyiz5J1K1nLVLme0EibGd2t" +
    "aYwggPKr2bGaIJBCENxIQbIPESwu6ZL5dTsmqtNRALGnVH/utvegBpsu7SMlCXE13CyI4EFD1c9wFrBNjSPx2ZjYrtFXfwKBgQDqAW10LhzF" +
    "pn6uyYDEixxm1ilvWg//0dS0ixr2hE+dPcDY1mz2S8OA+vkJ5kMWBn922UR7Ns7RpNoyHZUaY9rAvUtiU+25ZEmEGYEn9sadVw4CKEwQlM42" +
    "SQYRW0riBbOkcGxsbYbhOLC20+ti+OmV/JODAP2iP7VEc2moqaAmkwKBgQDleaoD7/ZQGy0fkno4HxEEkBeXvdHeR2c4eTphGgjnm+qeHonF" +
    "ZsTVhm8g8qdRECFrKqd0oJSk6sLREE9HrOE2HicKWgllSa3tmTc8bup0ZSIZcF3gnydAX19eZKU7XXx6gu79++5YgqNRiWvLDcHcqRoRE+8B" +
    "AWepF8762L2kwwKBgBMI6LFhqt99CqMHKx1Rv46x7w7qwZBqriW9hwT0gFFnG4/H6XcjdJTCVY2zmFNrVeUCCWsIa0xsX39iHqXV5450F3S5" +
    "JQZGnSBMvs/UaBWWZkJQqtdSc2/BAuhYh7/Y/OLsbjVnt2gMp3tHw8b6Pm3/7LPkWb1f90vJI5gfrDJXAoGBAMzwxXhSvOZ5/uitht3MUQSE" +
    "M63fZylfF76F9i92cvF2fCjPGTflOnGAaItCa0+oWlA9feRY7agDyg2wxT08Fr6gWzmRg8aj8OO77GranCVrlPKnOhA703BYPPIubKsCKQO5" +
    "H/xRHWKK+ZT+Z/imxrZth8wsw01gldWcX8wD+grFAoGBAMtCWVmb2Qbl2ioatqaBmLKQin6rqvnz3DSIPZQ+Vc+G3K2+Ayl5idVfv3N929c9" +
    "SddU0+LL7HrLUX9b8swAkMn6tSF6wcT4prCVkaa4Iti85Q/DMqs2He2Y+dGI6+ZUORih68SwP9w3J8LYPdBzuMGM3IJG8fyUkxPKSVbeixZq"
const rsaKeyPublic = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cJ8/jU1cyru5j4VaizE+nJUBvxWQJL+wE6X2xmaY7LiEY//GVN2vaF5iB+H9MCm6jfZ" +
    "URAsJn4FsWl3Y6FIpQ16jFK5OKJx2vxHxX82/gT8Ro9XDNMFcmYmG6uvL3ZiOEwGYnAfAVJ4L1++BCRQN9Q3+Z4IY5yp6qamx2ircPpIlkQh" +
    "ORrs+gNwXXA3P6g5gXfb0qi68n5Y1zBdW2Rl5c3Mo3oKsvY2mBYtL7kDqFzj1i5x5jFNvUXYsPvFBB6hxOg0S4Bl67pkgxROvC9L2oG54fhG" +
    "vnREPTza1iUoVZNMTuq48IWxGXcan/imF+ZTInP3Ee8Bh3xr4tl6UDqN+QIDAQAB"
const rsaEncrypted = "BSbuDZBPHmfDwENUr9qOtAaDYDpovWhSgoByCDa3hutGkehbJkJvbQxI0wKw5sX0vvgHsiirfpyNLDwOrivOLexcaqHcGR" +
    "SFYVgE4NLEcP+I0ZEAOxA1AuT45JSXB9kPUuodMQR99QT3t/Il5O3HaOqu5XOqJ5jEyCcPnXIBEmbF0HpOEvAHglfbiEUQ4UIdgZwFPJ" +
    "60O6TvnJRBPo1+RBXQiGxloMuW2vn048QFlYJ97/DeBqhEUMzJQ3xvKCqN72xSGS6jf0W26Vqr4VD8PSdD7SrKzZWaGVRTw05GqzkCq2" +
    "0KVUeTqN/Yq8fHL9NkMunxrcXA8OrHP+2lKQYfMA=="
const rsaSigned = "tk2p1HWxncYaHRIw7rqZsDJtIvUNNzvNQJgkn5qU3p2r2UjDWtWchHcsSRpOt2kp6cbQK59h7bvJTQTFDYU/to/JjASh0E" +
    "dcWtUq6dS/FAw0slqLVu4mJlu5+JbHtq2a2do5HAccNE7K3ollivmmPC2/K3sqogxrb2X14GxETwIUE7hk3FQA+WV1pyulj/AyF41WM5" +
    "t1ey3X3lvkb878upH7I7JtwNcxHH0mqYsm7NOol1TF58NYv7a+FqJSnMlZ95GaXut4BxRT+u7Ul3AQqJYeXeebv04WWHcZXfhz3a6lVU" +
    "SMOVs7v1hJNL5EkHpeM5Dl2KsQKCW2lMpnSzIPNQ=="
const hmacKey = "E8Kij04n2hg/j3y/d7M8RRmQLQHA+oCR7Uldec/f+kZH17nE0i7haenaM8tFrUljA+p0F/sHOLw+HPtmtcCl8xnqajmj" +
    "cTtfImZZD67uaIt30UkoMUQqOb62oR3cQ/fdWgIZTMk811HfE91UweqfalT6kAg5yh5wTc+xY5FGkLk="
const hmacSignature = "mCU9EWH5nXV58sDhUGfKYT45UGU5D3LyTtmsVqcobnbui2cg2e/muzegtDR3x5amAyb+4tpXXXPh/3M7ngblZA=="

const Buffer = require("buffer").Buffer;

function b64_2ua(b64: string) {
    return new Uint8Array(Buffer.from(b64, "base64"));
}  

function checkDecryptedData(decrypted: Uint8Array) {
    const decryptedDataString = Buffer.from(decrypted).toString("utf-8")
    if (decryptedDataString != data) throw new Error("Decrypted data is not the same as the original data")
}

export async function testExpoKryptom() {
    checkDecryptedData(await Aes.decrypt(b64_2ua(aesEncryptedData), b64_2ua(aesKey)))
    const privateKeyDecrypt = await Rsa.importPrivateKeyPkcs8(b64_2ua(rsaKeyPrivate), "OaepWithSha1")
    checkDecryptedData(await Rsa.decrypt(b64_2ua(rsaEncrypted), privateKeyDecrypt))
    const publicKeyVerify = await Rsa.importPublicKeySpki(b64_2ua(rsaKeyPublic), "PssWithSha256")
    if (!await Rsa.verify(b64_2ua(rsaSigned), dataBytes, publicKeyVerify)) throw new Error("Signature verification failed")
    if (!await Hmac.verify(b64_2ua(hmacSignature), dataBytes, { key: b64_2ua(hmacKey), algorithmIdentifier: "HmacSha512" })) throw new Error("HMAC verification failed")
}
