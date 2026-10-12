// Node.js'in şifre çözme ve güvenli karşılaştırma araçlarını içe aktarır.
import { createDecipheriv, timingSafeEqual } from "node:crypto";


// ============================================================
// 1. BTFW PAKET BİÇİMİNE AİT SABİTLER
// ============================================================

// Şifreli firmware dosyasının bize ait bir BTFW paketi olduğunu
// anlamak için dosyanın başında bulunması gereken imza.
const MAGIC = Buffer.from("BTFW");

// Eski BTFW paket biçiminin sürümü.
// Bu sürümde firmware kimlik bilgileri bulunmaz.
const LEGACY_FORMAT_VERSION = 1;

// Yeni BTFW paket biçiminin sürümü.
// Bu sürümde family, version ve target bilgileri bulunur.
const CURRENT_FORMAT_VERSION = 2;

// AES-256-GCM şifrelemede kullandığımız IV'nin uzunluğu.
// IV, aynı firmware tekrar şifrelense bile farklı çıktı oluşmasını sağlar.
const IV_LENGTH = 12;

// AES-GCM doğrulama etiketinin uzunluğu.
// Paket değiştirilmişse veya yanlış anahtar kullanılmışsa
// bu etiket sayesinde işlem başarısız olur.
const AUTH_TAG_LENGTH = 16;

// Metadata'nın kaç bayt olduğunu belirten sayıyı saklamak için
// paket içerisinde 4 baytlık alan kullanıyoruz.
const METADATA_LENGTH_SIZE = 4;

// Eski v1 paketinin sabit başlık uzunluğu:
// 4 bayt BTFW imzası
// 1 bayt paket biçimi sürümü
// 12 bayt IV
// 16 bayt doğrulama etiketi
const LEGACY_HEADER_LENGTH =
    MAGIC.length + 1 + IV_LENGTH + AUTH_TAG_LENGTH;

// Yeni v2 paketinin metadata haricindeki sabit başlık uzunluğu:
// 4 bayt BTFW imzası
// 1 bayt paket biçimi sürümü
// 4 bayt metadata uzunluğu
// 12 bayt IV
// 16 bayt doğrulama etiketi
const CURRENT_FIXED_HEADER_LENGTH =
    MAGIC.length +
    1 +
    METADATA_LENGTH_SIZE +
    IV_LENGTH +
    AUTH_TAG_LENGTH;

// AES-256 anahtarı 32 bayttır.
// Hexadecimal metin olarak her bayt 2 karakterle yazıldığı için
// anahtarın toplam uzunluğu 64 karakter olmalıdır.
const KEY_LENGTH_HEX = 64;

// Configurator yalnızca bu iki firmware ailesini kabul edecek.
// Tanınmayan bir family değeri daha sonra reddedilecek.
const SUPPORTED_FAMILIES = new Set(["INAV", "BETAFLIGHT"]);


// ============================================================
// 2. PAKETİN TEMEL KONTROLLERİ
// ============================================================

/**
 * Şifre çözme işleminden önce paketin ve anahtarın
 * temel kurallara uygun olup olmadığını kontrol eder.
 *
 * @param {Buffer} encryptedPackage Okunan şifreli BTFW dosyası
 * @param {string} keyHex 64 karakterlik hexadecimal AES anahtarı
 */
function validateEncryptedPackage(encryptedPackage, keyHex) {
    // Gelen verinin Node.js Buffer türünde olup olmadığını kontrol eder.
    // Buffer, ikili dosya verisini bellekte tutan yapıdır.
    if (!Buffer.isBuffer(encryptedPackage)) {
        throw new Error(
            "Encrypted firmware must be provided as a Buffer.",
        );
    }

    // Dosyanın yalnızca BTFW imzasından oluşması yeterli değildir.
    // İmzadan sonra en azından paket sürümü ve paket verileri bulunmalıdır.
    if (encryptedPackage.length <= MAGIC.length) {
        throw new Error("Encrypted firmware package is too small.");
    }

    // Anahtarın mevcut olmasını, yalnızca hexadecimal karakterlerden
    // oluşmasını ve tam olarak 64 karakter olmasını kontrol eder.
    if (
        !keyHex ||
        !new RegExp(`^[0-9a-fA-F]{${KEY_LENGTH_HEX}}$`).test(keyHex)
    ) {
        throw new Error(
            "Firmware encryption key is missing or invalid.",
        );
    }

    // Dosyanın ilk dört baytını alır.
    const packageMagic = encryptedPackage.subarray(0, MAGIC.length);

    // İlk dört baytı beklenen BTFW imzasıyla güvenli şekilde karşılaştırır.
    // Eşleşmiyorsa bu dosya geçerli bir BTFW paketi değildir.
    if (!timingSafeEqual(packageMagic, MAGIC)) {
        throw new Error("Invalid encrypted firmware signature.");
    }
}
// ============================================================
// 3. FIRMWARE METADATA BİLGİLERİNİ DOĞRULAMA
// ============================================================

/**
 * V2 paketinden okunan firmware kimlik bilgilerini kontrol eder.
 *
 * @param {object} metadata Paketin içinden okunan kimlik bilgileri
 * @param {object|null} expectedMetadata Kullanıcının seçtiği firmware kimliği
 */
function validateMetadata(metadata, expectedMetadata) {
    // Metadata'nın normal bir JavaScript nesnesi olması gerekir.
    if (
        !metadata ||
        typeof metadata !== "object" ||
        Array.isArray(metadata)
    ) {
        throw new Error("Firmware metadata is invalid.");
    }

    // Firmware ailesi yalnızca INAV veya BETAFLIGHT olabilir.
    if (!SUPPORTED_FAMILIES.has(metadata.family)) {
        throw new Error(
            `Unsupported firmware family: ${metadata.family}`,
        );
    }

    // Sürüm bilgisi 8.0.0 veya 4.4.3 gibi x.y.z biçiminde olmalıdır.
    if (
        typeof metadata.version !== "string" ||
        !/^\d+\.\d+\.\d+$/.test(metadata.version)
    ) {
        throw new Error("Firmware metadata version is invalid.");
    }

    // Hedef adı yalnızca büyük harf, sayı, alt çizgi
    // ve kısa çizgi içerebilir.
    if (
        typeof metadata.target !== "string" ||
        !/^[A-Z0-9_-]+$/.test(metadata.target)
    ) {
        throw new Error("Firmware metadata target is invalid.");
    }

    // Kullanıcının seçtiği beklenen firmware bilgisi verilmemişse
    // paketin kendi bilgilerinin geçerli olması yeterlidir.
    if (!expectedMetadata) {
        return;
    }

    // Paketteki firmware ailesini kullanıcının seçimiyle karşılaştırır.
    if (metadata.family !== expectedMetadata.family) {
        throw new Error(
            `Firmware family mismatch: expected ` +
            `${expectedMetadata.family}, received ${metadata.family}.`,
        );
    }

    // Paketteki firmware sürümünü kullanıcının seçimiyle karşılaştırır.
    if (metadata.version !== expectedMetadata.version) {
        throw new Error(
            `Firmware version mismatch: expected ` +
            `${expectedMetadata.version}, received ${metadata.version}.`,
        );
    }

    // Paketteki hedef kartı kullanıcının seçimiyle karşılaştırır.
    if (metadata.target !== expectedMetadata.target) {
        throw new Error(
            `Firmware target mismatch: expected ` +
            `${expectedMetadata.target}, received ${metadata.target}.`,
        );
    }
}
// ============================================================
// 4. ESKİ BTFW V1 PAKETİNİ ÇÖZME
// ============================================================

/**
 * Metadata içermeyen eski BTFW v1 paketini çözer.
 *
 * V1 paket sıralaması:
 * BTFW | sürüm | IV | doğrulama etiketi | şifreli HEX
 *
 * @param {Buffer} encryptedPackage Şifreli BTFW v1 paketi
 * @param {string} keyHex AES-256 anahtarının hexadecimal hâli
 * @returns {Buffer} Çözülmüş Intel HEX verisi
 */
function decryptLegacyPackage(encryptedPackage, keyHex) {
    // Paket başlıktan daha büyük olmalıdır.
    // Yalnızca başlık varsa içerisinde şifrelenmiş HEX bulunmaz.
    if (encryptedPackage.length <= LEGACY_HEADER_LENGTH) {
        throw new Error(
            "Legacy encrypted firmware package is too small.",
        );
    }

    // BTFW imzası ve sürüm baytından sonra IV başlar.
    const ivStart = MAGIC.length + 1;

    // IV bittikten sonra doğrulama etiketi başlar.
    const authTagStart = ivStart + IV_LENGTH;

    // Doğrulama etiketi bittikten sonra şifreli HEX başlar.
    const ciphertextStart = authTagStart + AUTH_TAG_LENGTH;

    // Paket içerisinden IV bölümünü alır.
    const iv = encryptedPackage.subarray(
        ivStart,
        authTagStart,
    );

    // Paket içerisinden AES-GCM doğrulama etiketini alır.
    const authenticationTag = encryptedPackage.subarray(
        authTagStart,
        ciphertextStart,
    );

    // Başlıktan sonra kalan bölüm şifrelenmiş HEX verisidir.
    const ciphertext = encryptedPackage.subarray(ciphertextStart);

    // 64 hexadecimal karakterlik metni,
    // AES'in kullanacağı 32 baytlık anahtara dönüştürür.
    const key = Buffer.from(keyHex, "hex");

    try {
        // AES-256-GCM çözme aracını anahtar ve IV ile oluşturur.
        const decipher = createDecipheriv(
            "aes-256-gcm",
            key,
            iv,
        );

        // Paketten okunan doğrulama etiketini çözücüye verir.
        decipher.setAuthTag(authenticationTag);

        // Şifreli veriyi çözer ve parçaları tek Buffer hâline getirir.
        const plaintext = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final(),
        ]);

        // Intel HEX dosyalarının satırları ":" karakteriyle başlar.
        // Çözülen veri boşsa veya ":" ile başlamıyorsa geçerli HEX değildir.
        if (
            plaintext.length === 0 ||
            plaintext[0] !== ":".charCodeAt(0)
        ) {
            throw new Error(
                "Decrypted data is not an Intel HEX file.",
            );
        }

        // Kontrolleri geçen açık HEX verisini geri döndürür.
        return plaintext;
    } catch {
        // Yanlış anahtar, bozuk paket veya geçersiz doğrulama etiketi
        // gibi durumlarda kullanıcıya kontrollü bir hata verir.
        throw new Error(
            "Firmware decryption failed: wrong key or corrupted package.",
        );
    }
}
// ============================================================
// 5. YENİ BTFW V2 PAKETİNİ ÇÖZME
// ============================================================

/**
 * Metadata içeren yeni BTFW v2 paketini çözer.
 *
 * V2 paket sıralaması:
 * BTFW | sürüm | metadata uzunluğu | IV |
 * doğrulama etiketi | metadata | şifreli HEX
 *
 * @param {Buffer} encryptedPackage Şifreli BTFW v2 paketi
 * @param {string} keyHex AES-256 anahtarının hexadecimal hâli
 * @param {object|null} expectedMetadata Beklenen firmware kimliği
 * @returns {Buffer} Çözülmüş Intel HEX verisi
 */
function decryptCurrentPackage(
    encryptedPackage,
    keyHex,
    expectedMetadata,
) {
    // Paket, sabit başlık bölümünden daha büyük olmalıdır.
    if (encryptedPackage.length <= CURRENT_FIXED_HEADER_LENGTH) {
        throw new Error(
            "Encrypted firmware v2 package is too small.",
        );
    }

    // BTFW imzasından ve sürüm baytından sonra
    // 4 baytlık metadata uzunluğu alanı başlar.
    const metadataLengthStart = MAGIC.length + 1;
    const metadataLengthEnd =
        metadataLengthStart + METADATA_LENGTH_SIZE;

    // Metadata uzunluğu alanından sonra IV başlar.
    const ivStart = metadataLengthEnd;

    // IV bittikten sonra doğrulama etiketi başlar.
    const authTagStart = ivStart + IV_LENGTH;

    // Doğrulama etiketi bittikten sonra metadata başlar.
    const metadataStart = authTagStart + AUTH_TAG_LENGTH;

    // Paketteki 4 baytlık metadata uzunluğu alanını alır.
    const metadataLengthBuffer = encryptedPackage.subarray(
        metadataLengthStart,
        metadataLengthEnd,
    );

    // 4 baytlık büyük uçlu sayıyı JavaScript sayısına dönüştürür.
    const metadataLength = metadataLengthBuffer.readUInt32BE(0);

    // Metadata'nın paket içerisinde biteceği konumu hesaplar.
    const metadataEnd = metadataStart + metadataLength;

    // Metadata boş olamaz.
    if (metadataLength === 0) {
        throw new Error("Firmware metadata is empty.");
    }

    // Metadata'nın bitiş konumu dosya boyutuna eşit veya büyükse
    // paket içerisinde şifreli HEX verisi kalmamış demektir.
    if (metadataEnd >= encryptedPackage.length) {
        throw new Error(
            "Firmware metadata length exceeds package size.",
        );
    }

    // Paket içerisinden IV'yi ayırır.
    const iv = encryptedPackage.subarray(
        ivStart,
        authTagStart,
    );

    // Paket içerisinden AES-GCM doğrulama etiketini ayırır.
    const authenticationTag = encryptedPackage.subarray(
        authTagStart,
        metadataStart,
    );

    // Paket içerisinden JSON metadata verisini ayırır.
    const metadataBuffer = encryptedPackage.subarray(
        metadataStart,
        metadataEnd,
    );

    // Metadata'dan sonra kalan bölüm şifrelenmiş HEX verisidir.
    const ciphertext = encryptedPackage.subarray(metadataEnd);

    // Şifreleyicide AAD olarak kullanılan başlığın
    // aynısını yeniden oluşturur.
    const authenticatedHeader = Buffer.concat([
        MAGIC,
        Buffer.from([CURRENT_FORMAT_VERSION]),
        metadataLengthBuffer,
        metadataBuffer,
    ]);

    // Hexadecimal anahtar metnini 32 baytlık AES anahtarına çevirir.
    const key = Buffer.from(keyHex, "hex");

    let plaintext;

    try {
        // AES-256-GCM çözme aracını anahtar ve IV ile oluşturur.
        const decipher = createDecipheriv(
            "aes-256-gcm",
            key,
            iv,
        );

        // Metadata ve paket başlığını güvenlik doğrulamasına bağlar.
        decipher.setAAD(authenticatedHeader);

        // Paketten okunan doğrulama etiketini çözücüye verir.
        decipher.setAuthTag(authenticationTag);

        // Şifreli HEX verisini çözer.
        plaintext = Buffer.concat([
            decipher.update(ciphertext),
            decipher.final(),
        ]);
    } catch {
        // Yanlış anahtar, değiştirilmiş metadata veya bozuk paket
        // varsa AES-GCM doğrulaması başarısız olur.
        throw new Error(
            "Firmware decryption failed: wrong key or corrupted package.",
        );
    }

    let metadata;

    try {
        // Metadata baytlarını UTF-8 metne çevirir,
        // ardından JSON metnini JavaScript nesnesine dönüştürür.
        metadata = JSON.parse(metadataBuffer.toString("utf8"));
    } catch {
        throw new Error("Firmware metadata is not valid JSON.");
    }

    // Metadata içeriğini ve kullanıcının seçtiği firmware ile
    // eşleşip eşleşmediğini kontrol eder.
    validateMetadata(metadata, expectedMetadata);

    // Çözülmüş verinin Intel HEX olup olmadığını kontrol eder.
    if (
        plaintext.length === 0 ||
        plaintext[0] !== ":".charCodeAt(0)
    ) {
        throw new Error(
            "Decrypted data is not an Intel HEX file.",
        );
    }

    // Doğrulanmış ve çözülmüş HEX verisini RAM'den geri döndürür.
    return plaintext;
}


// ============================================================
// 6. PAKET SÜRÜMÜNE GÖRE DOĞRU ÇÖZÜCÜYÜ SEÇME
// ============================================================
/**
 * Şifreli firmware paketinin sürümünü belirler ve
 * paketi uygun çözme fonksiyonuna yönlendirir.
 *
 * @param {Buffer} encryptedPackage Şifreli BTFW paketi
 * @param {string} keyHex AES-256 şifreleme anahtarı
 * @param {object|null} expectedMetadata Seçilmesi beklenen firmware kimliği
 * @returns {Buffer} Çözülmüş Intel HEX verisi
 */
export function decryptFirmwarePackage(
    encryptedPackage,
    keyHex,
    expectedMetadata = null,
) {
    // Paket ve anahtar üzerinde ortak temel kontrolleri yapar.
    validateEncryptedPackage(encryptedPackage, keyHex);

    // BTFW imzasından hemen sonraki bayt paket biçimi sürümüdür.
    //
    // Konum: 0  1  2  3  4
    // Veri:  B  T  F  W  sürüm
    const formatVersion = encryptedPackage[MAGIC.length];

    // Paket biçimi v1 ise eski paket çözücüsünü kullanır.
    if (formatVersion === LEGACY_FORMAT_VERSION) {
        return decryptLegacyPackage(encryptedPackage, keyHex);
    }

    // Paket biçimi v2 ise metadata destekli yeni çözücüyü kullanır.
    if (formatVersion === CURRENT_FORMAT_VERSION) {
        return decryptCurrentPackage(
            encryptedPackage,
            keyHex,
            expectedMetadata,
        );
    }

    // Paket sürümü 1 veya 2 değilse yapısını bilmediğimiz için
    // güvenli biçimde işlemi durdurur.
    throw new Error(
        `Unsupported encrypted firmware version: ${formatVersion}`,
    );
}