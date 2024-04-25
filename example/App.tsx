import { Aes, HmacKey, PrivateRsaKeyJwk, PublicRsaKeyJwk, Rsa, RsaAlgorithm, RsaKeyPair, Hmac, StrongRandom, Digest } from "expo-kryptom";
import { useReducer, useState } from "react";
import { StyleSheet, Text, View, Button, Alert } from "react-native";
import { testExpoKryptom } from "./Test";

const Buffer = require("buffer").Buffer;
const bytes = [0x3a, 0x13, 0x68, 0x1a, 0x8a, 0xe2, 0x96, 0x50];

function ua2b64(ua: Uint8Array) {
  return Buffer.from(ua).toString("base64");
}

type RsaState = {
  status: 'NOT_INITIALIZED',
} | {
  status: 'INITIALIZED',
  keyPair: RsaKeyPair,
};

const initial: RsaState = {
  status: 'NOT_INITIALIZED',
};

type RsaAction = {
  type: "initialize",
  key: RsaKeyPair,
}

function rsaReducer(state: RsaState, action: RsaAction): RsaState {
  switch (action.type) {
    case "initialize":
      return {
        ...state,
        status: 'INITIALIZED',
        keyPair: action.key,
      };
    default:
      throw new Error("Invalid action type");
  }
}

type HmacState = {
  status: 'NOT_INITIALIZED',
} | {
  status: 'INITIALIZED',
  keydata: HmacKey
}

type HmacAction = {
  type: "initialize",
  keydata: HmacKey,
}

function hmacReducer(state: HmacState, action: HmacAction): HmacState {
  switch (action.type) {
    case "initialize":
      return {
        ...state,
        status: 'INITIALIZED',
        keydata: action.keydata,
      };
    default:
      throw new Error("Invalid action type");
  }
}

export default function App() {

  const [rsaEncryptionState, rsaEncryptionDispatch] = useReducer(rsaReducer, initial as RsaState);
  const [rsaSignatureState, rsaSignatureDispatch] = useReducer(rsaReducer, initial as RsaState);

  const [privateKeyJwk, setPrivateKeyJwk] = useState<PrivateRsaKeyJwk | undefined>(undefined);
  const [publicKeyJwk, setPublicKeyJwk] = useState<PublicRsaKeyJwk | undefined>(undefined);
  const [privateKeyPkcs8, setPrivateKeyPkcs8] = useState<Uint8Array | undefined>(undefined);
  const [publicKeySpki, setPublicKeySpki] = useState<Uint8Array | undefined>(undefined);

  const [hmacState, hmacDispatch] = useReducer(hmacReducer, { status: 'NOT_INITIALIZED' } as HmacState);

  return (
    <View style={styles.container}>
      <Text>{ua2b64(new Uint8Array(bytes))}</Text>
      <Button
        onPress={async () => {
          const key = await Aes.generateKey("AesCbcPkcs7", 256);
          console.log("Got key");
          console.log(JSON.stringify(key));
          const encrypted = await Aes.encrypt(
            new Uint8Array(bytes),
            key,
            null,
          );
          console.log("Encrypted");
          console.log(ua2b64(encrypted));
          const decrypted = await Aes.decrypt(encrypted, key);
          console.log("Decrypted");
          console.log(ua2b64(decrypted));
        }}
        title="AES Encrypt then decrypt"
      />

      {rsaSignatureState.status === 'INITIALIZED' ? (
        <>
          <Button
            onPress={async () => {
              if (rsaSignatureState.status !== 'INITIALIZED') {
                Alert.alert("Key not initialized");
                return;
              }

              if (rsaSignatureState.keyPair.algorithmIdentifier !== "PssWithSha256") {
                Alert.alert("Algorithm not supported for signature", rsaSignatureState.keyPair.algorithmIdentifier);
                return;
              }

              const signature = await Rsa.signature(
                new Uint8Array(bytes),
                rsaSignatureState.keyPair,
              );
              console.log("Signature");
              console.log(ua2b64(signature));

              const verified = await Rsa.verify(signature, new Uint8Array(bytes), rsaSignatureState.keyPair);
              console.log("Verified");
              console.log(verified);
            }}
            title="RSA Sign then verify"
          />
        </>
      ) : (
        <>
          <Button
            onPress={async () => {
              const key = await Rsa.generateKey("PssWithSha256", 2048);
              console.log("Got key");
              console.log(key);

              rsaSignatureDispatch({
                type: "initialize",
                key: key,
              })
            }
            }
            title="Generate RSA Signature key"
          />
        </>
      )}

      {rsaEncryptionState.status === 'INITIALIZED' ? (
        <>
          <Button
            onPress={async () => {
              if (rsaEncryptionState.status !== 'INITIALIZED') {
                Alert.alert("Key not initialized");
                return;
              }

              const encrypted = await Rsa.encrypt(
                new Uint8Array(bytes),
                rsaEncryptionState.keyPair,
              );
              console.log("Encrypted");
              console.log(ua2b64(encrypted));

              const decrypted = await Rsa.decrypt(encrypted, rsaEncryptionState.keyPair);
              console.log("Decrypted");
              console.log(ua2b64(decrypted));
            }}
            title="RSA Encrypt then decrypt"
          />
          <Button
            onPress={async () => {
              const key = await Rsa.exportPrivateKeyJwk(rsaEncryptionState.keyPair);
              console.log("Got JWK private key");
              console.log(key);
              setPrivateKeyJwk(key);
            }}
            title="Export to Private JWK"
          />
          {privateKeyJwk != undefined && (
            <Button
              onPress={async () => {
                const key = await Rsa.importPrivateKeyJwk(privateKeyJwk!, rsaEncryptionState.keyPair.algorithmIdentifier);
                console.log("Imported JWK private key");
                console.log(key);
              }}
              title="Import Private JWK"
            />
          )}
          <Button
            onPress={async () => {
              const key = await Rsa.exportPublicKeyJwk(rsaEncryptionState.keyPair);
              console.log("Got JWK Public key");
              console.log(key);
              setPublicKeyJwk(key);
            }}
            title="Export to Public JWK"
          />
          {publicKeyJwk != undefined && (
            <Button
              onPress={async () => {
                console.log(publicKeyJwk);
                const key = await Rsa.importPublicKeyJwk(publicKeyJwk!, rsaEncryptionState.keyPair.algorithmIdentifier);
                console.log("Imported JWK public key");
                console.log(key);
              }}
              title="Import Public JWK"
            />
          )}
          <Button
            onPress={async () => {
              const key = await Rsa.exportPrivateKeyPkcs8(rsaEncryptionState.keyPair);
              console.log("Got Private key in PKCS8 format");
              console.log(key);
              setPrivateKeyPkcs8(key);
            }}
            title="Export to Private PKCS8"
          />
          {privateKeyPkcs8 != undefined && (
            <>
              <Button
                onPress={async () => {
                  const key = await Rsa.importPrivateKeyPkcs8(privateKeyPkcs8!, rsaEncryptionState.keyPair.algorithmIdentifier);
                  console.log("Imported PKCS8 private key");
                  console.log(key);
                }}
                title="Import Private PKCS8"
              />
              <Button
                onPress={async () => {
                  const key = await Rsa.importKeyPair(privateKeyPkcs8, rsaEncryptionState.keyPair.algorithmIdentifier);
                  console.log("Imported key pair");
                  console.log(key);
                }}
                title="Import key pair"
              />
            </>
          )}
          <Button
            onPress={async () => {
              const key = await Rsa.exportPublicKeySpki(rsaEncryptionState.keyPair);
              console.log("Got Public key in SPKI format");
              console.log(key);
              setPublicKeySpki(key);
            }}
            title="Export to Public SPKI"
          />
          {publicKeySpki != undefined && (
            <Button
              onPress={async () => {
                const key = await Rsa.importPublicKeySpki(publicKeySpki!, rsaEncryptionState.keyPair.algorithmIdentifier);
                console.log("Imported SPKI public key");
                console.log(key);
              }}
              title="Import Public SPKI"
            />
          )}
        </>
      ) : (
        <>
          <Button
            onPress={async () => {
              const key = await Rsa.generateKey("OaepWithSha256", 2048);
              console.log("Got key");
              console.log(key);

              rsaEncryptionDispatch({
                type: "initialize",
                key: key,
              })
            }}
            title="Generate RSA Encryption key"
          />
        </>
      )}

      {hmacState.status === 'INITIALIZED' ? (
        <>
          <Button
            onPress={async () => {
              if (hmacState.status !== 'INITIALIZED') {
                Alert.alert("Key not initialized");
                return;
              }

              const signature = await Hmac.sign(
                new Uint8Array(bytes),
                hmacState.keydata
              );
              console.log("Signature");
              console.log(ua2b64(signature));

              const verified = await Hmac.verify(
                signature,
                new Uint8Array(bytes),
                hmacState.keydata
              );
              console.log("Verified");
              console.log(verified);
            }}
            title="HMAC Sign then verify"
          />
        </>
      ) : (
        <>
          <Button
            onPress={async () => {
              const key = await Hmac.generateKey("HmacSha512");
              console.log("Got key");
              console.log(JSON.stringify(key));
              hmacDispatch({
                type: "initialize",
                keydata: key,
              });
            }}
            title="Generate HMAC key"
          />
        </>
      )}
      <Button
        onPress={async () => {
          const digest = await Digest.sha256(new Uint8Array(bytes));
          console.log("Sha256");
          console.log(ua2b64(digest));
        }}
        title="Sha256"
      />
      <Button
        onPress={() => {
          const random = StrongRandom.randomBytes(10);
          console.log("Random bytes");
          console.log(ua2b64(random));
        }}
        title="10 random byes"
      />
      <Button
        onPress={async () => {
          const uuid = StrongRandom.randomUUID();
          console.log("Random UUID");
          console.log(uuid);
        }}
        title="Random UUID"
      />
      <Button
        onPress={async () => {
          try {
            await Rsa.generateKey("ThisAlgorithmDoesNotExist", 2048)
            console.log("Success - this should not happen")
          } catch (e) {
            console.log("Failed to generate key (as expected)") 
            console.log((e as Error).message)
          }
        }}
        title="Generate key with wrong algorithm"
      />
      <Button
        onPress={async () => {
          await testExpoKryptom()
          console.log("Everything works!")
        }}
        title="Run tests"
      />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
  },
});
