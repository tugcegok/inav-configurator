import { createDecipheriv, timingSafeEqual } from "node:crypto";

const MAGIC = Buffer.from("BTFW");
const SUPPORTED_FORMAT_VERSION = 1;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const HEADER_LENGTH = MAGIC.length + 1 + IV_LENGTH + AUTH_TAG_LENGTH;
const KEY_LENGTH_HEX = 64;

export function decryptFirmwarePackage(encryptedPackage, keyHex) {
    if (!Buffer.isBuffer(encryptedPackage)) {
        throw new Error("Encrypted firmware must be provided as a Buffer.");
    }

    if (encryptedPackage.length <= HEADER_LENGTH) {
        throw new Error("Encrypted firmware package is too small.");
    }

    if (!keyHex || !new RegExp(`^[0-9a-fA-F]{${KEY_LENGTH_HEX}}$`).test(keyHex)) {
        throw new Error("Firmware encryption key is missing or invalid.");
    }

    const packageMagic = encryptedPackage.subarray(0, MAGIC.length);

    if (!timingSafeEqual(packageMagic, MAGIC)) {
        throw new Error("Invalid encrypted firmware signature.");
    }

    const formatVersion = encryptedPackage[MAGIC.length];

    if (formatVersion !== SUPPORTED_FORMAT_VERSION) {
        throw new Error(`Unsupported encrypted firmware version: ${formatVersion}`);
    }

    const ivStart = MAGIC.length + 1;
    const authTagStart = ivStart + IV_LENGTH;
    const ciphertextStart = authTagStart + AUTH_TAG_LENGTH;

    const iv = encryptedPackage.subarray(ivStart, authTagStart);
    const authenticationTag = encryptedPackage.subarray(
        authTagStart,
        ciphertextStart,
    );
    const ciphertext = encryptedPackage.subarray(ciphertextStart);
    const key = Buffer.from(keyHex, "hex");

    try {
        const decipher = createDecipheriv("aes-256-gcm", key, iv);
        decipher.setAuthTag(authenticationTag);

        const plaintext = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final(),
        ]);

        if (plaintext.length === 0 || plaintext[0] !== ":".charCodeAt(0)) {
            throw new Error("Decrypted data is not an Intel HEX file.");
        }

        return plaintext;
    } catch {
        throw new Error(
            "Firmware decryption failed: wrong key or corrupted package.",
        );
    }
}