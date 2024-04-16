import * as ExpoKryptom from "expo-kryptom";
import { StyleSheet, Text, View, Button } from "react-native";

const Buffer = require("buffer").Buffer;
const bytes = [0x3a, 0x13, 0x68, 0x1a, 0x8a, 0xe2, 0x96, 0x50];

function ua2b64(ua: Uint8Array) {
  return Buffer.from(ua).toString("base64");
}

export default function App() {
  return (
    <View style={styles.container}>
      <Text>{ua2b64(new Uint8Array(bytes))}</Text>
      <Button
        onPress={async () => {
          const key = await ExpoKryptom.Aes.generateKey(256);
          console.log("Got key");
          console.log(ua2b64(key));
          const encrypted = await ExpoKryptom.Aes.encrypt(
            new Uint8Array(bytes),
            key,
            null,
          );
          console.log("Encrypted");
          console.log(ua2b64(encrypted));
          const decrypted = await ExpoKryptom.Aes.decrypt(encrypted, key);
          console.log("Decrypted");
          console.log(ua2b64(decrypted));
        }}
        title="Encrypt then decrypt"
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
