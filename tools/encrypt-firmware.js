import { createCipheriv, randomBytes } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const MAGIC = Buffer.from("BTFW");
const FORMAT_VERSION = 2;
const IV_LENGTH = 12;
const KEY_LENGTH_HEX = 64;
const METADATA_LENGTH_SIZE = 4;

const SUPPORTED_FAMILIES = new Set(["INAV", "BETAFLIGHT"]);

async function main() {
    const inputPath = process.argv[2];
    const outputPath = process.argv[3];
    const family = process.argv[4]?.toUpperCase();
    const firmwareVersion = process.argv[5];
    const target = process.argv[6]?.toUpperCase();
    const keyHex = process.env.FIRMWARE_ENCRYPTION_KEY;

    if (
        !inputPath ||
        !outputPath ||
        !family ||
        !firmwareVersion ||
        !target
    ) {
        throw new Error(
            "Usage: node tools/encrypt-firmware.js " +
            "<input.hex> <output.btfw> <INAV|BETAFLIGHT> " +
            "<firmware-version> <target>",
        );
    }

    if (!SUPPORTED_FAMILIES.has(family)) {
        throw new Error(
            "Firmware family must be either INAV or BETAFLIGHT.",
        );
    }

    if (!/^\d+\.\d+\.\d+$/.test(firmwareVersion)) {
        throw new Error(
            "Firmware version must use the x.y.z format.",
        );
    }

    if (!/^[A-Z0-9_-]+$/.test(target)) {
        throw new Error(
            "Firmware target may contain only letters, numbers, _ and -.",
        );
    }

    if (
        !keyHex ||
        !new RegExp(`^[0-9a-fA-F]{${KEY_LENGTH_HEX}}$`).test(keyHex)
    ) {
        throw new Error(
            "FIRMWARE_ENCRYPTION_KEY must contain exactly " +
            "64 hexadecimal characters.",
        );
    }

    if (path.extname(inputPath).toLowerCase() !== ".hex") {
        throw new Error("The input file must have a .hex extension.");
    }

    const plaintext = await readFile(inputPath);

    if (plaintext.length === 0 || plaintext[0] !== ":".charCodeAt(0)) {
        throw new Error(
            "The input does not appear to be an Intel HEX file.",
        );
    }

    const metadata = {
        family,
        version: firmwareVersion,
        target,
    };

    const metadataBuffer = Buffer.from(
        JSON.stringify(metadata),
        "utf8",
    );

    const metadataLength = Buffer.alloc(METADATA_LENGTH_SIZE);
    metadataLength.writeUInt32BE(metadataBuffer.length);

    const versionBuffer = Buffer.from([FORMAT_VERSION]);

    const authenticatedHeader = Buffer.concat([
        MAGIC,
        versionBuffer,
        metadataLength,
        metadataBuffer,
    ]);

    const key = Buffer.from(keyHex, "hex");
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv("aes-256-gcm", key, iv);

    cipher.setAAD(authenticatedHeader);

    const ciphertext = Buffer.concat([
        cipher.update(plaintext),
        cipher.final(),
    ]);

    const authenticationTag = cipher.getAuthTag();

    const encryptedPackage = Buffer.concat([
        MAGIC,
        versionBuffer,
        metadataLength,
        iv,
        authenticationTag,
        metadataBuffer,
        ciphertext,
    ]);

    await mkdir(path.dirname(outputPath), { recursive: true });
    await writeFile(outputPath, encryptedPackage);

    console.log(`Encrypted firmware created: ${outputPath}`);
    console.log(`Firmware family: ${family}`);
    console.log(`Firmware version: ${firmwareVersion}`);
    console.log(`Firmware target: ${target}`);
    console.log(`Plaintext size: ${plaintext.length} bytes`);
    console.log(`Encrypted size: ${encryptedPackage.length} bytes`);
}

main().catch((error) => {
    console.error(`Encryption failed: ${error.message}`);
    process.exitCode = 1;
});