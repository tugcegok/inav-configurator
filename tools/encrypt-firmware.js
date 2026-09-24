
import { createCipheriv, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const MAGIC = Buffer.from("BTFW");
const FORMAT_VERSION = Buffer.from([1]);
const IV_LENGTH = 12;
const KEY_LENGTH_HEX = 64;

async function main() {
    const inputPath = process.argv[2];
    const outputPath = process.argv[3] ?? "resources/firmware/matekf405.btfw";
    const keyHex = process.env.FIRMWARE_ENCRYPTION_KEY;

    if (!inputPath) {
        throw new Error(
            "Usage: node tools/encrypt-firmware.js <input.hex> [output.btfw]",
        );
    }

    if (!keyHex || !new RegExp(`^[0-9a-fA-F]{${KEY_LENGTH_HEX}}$`).test(keyHex)) {
        throw new Error(
            "FIRMWARE_ENCRYPTION_KEY must contain exactly 64 hexadecimal characters.",
        );
    }

    if (path.extname(inputPath).toLowerCase() !== ".hex") {
        throw new Error("The input file must have a .hex extension.");
    }

    const plaintext = await readFile(inputPath);

    if (plaintext.length === 0 || plaintext[0] !== ":".charCodeAt(0)) {
        throw new Error("The input does not appear to be an Intel HEX file.");
    }

    const key = Buffer.from(keyHex, "hex");
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv("aes-256-gcm", key, iv);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);

    const authenticationTag = cipher.getAuthTag();

    const encryptedPackage = Buffer.concat([
        MAGIC,
        FORMAT_VERSION,
        iv,
        authenticationTag,
        ciphertext,
    ]);

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, encryptedPackage);

    console.log(`Encrypted firmware created: ${outputPath}`);
    console.log(`Plaintext size: ${plaintext.length} bytes`);
    console.log(`Encrypted size: ${encryptedPackage.length} bytes`);
}

main().catch((error) => {
    console.error(`Encryption failed: ${error.message}`);
    process.exitCode = 1;
});