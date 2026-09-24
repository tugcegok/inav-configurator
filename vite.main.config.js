import { defineConfig, mergeConfig } from 'vite';
import {
  getBuildConfig,
  getBuildDefine,
  esmodule,
  pluginHotRestart,
} from './vite.base.config';
import native from 'vite-plugin-native';

// https://vitejs.dev/config
export default defineConfig((env) => {
  /** @type {import('vite').ConfigEnv<'build'>} */
  const forgeEnv = env;
  const { forgeConfigSelf } = forgeEnv;

  /*
   * Firmware anahtarı kaynak koda yazılmaz.
   * Derleme sırasında FIRMWARE_ENCRYPTION_KEY ortam değişkeninden alınır.
   */
  const firmwareEncryptionKey = process.env.FIRMWARE_ENCRYPTION_KEY;

  /*
   * AES-256 anahtarı 32 byte, yani 64 hexadecimal karakter olmalıdır.
   * Anahtar yoksa veya geçersizse paket oluşturulması durdurulur.
   */
  if (
    !firmwareEncryptionKey ||
    !/^[0-9a-fA-F]{64}$/.test(firmwareEncryptionKey)
  ) {
    throw new Error(
      'FIRMWARE_ENCRYPTION_KEY must contain exactly 64 hexadecimal characters.',
    );
  }

  const define = getBuildDefine(forgeEnv);

  /*
   * main.js içindeki process.env.FIRMWARE_ENCRYPTION_KEY ifadesi,
   * Vite derlemesi sırasında gerçek anahtar değeriyle değiştirilir.
   *
   * Böylece kurulan uygulama çalışırken ayrıca bir ortam değişkenine
   * ihtiyaç duymaz. Anahtar kaynak koda veya Git deposuna yazılmaz.
   */
  define['process.env.FIRMWARE_ENCRYPTION_KEY'] =
    JSON.stringify(firmwareEncryptionKey);

  const config = {
    build: {
      lib: {
        entry: forgeConfigSelf.entry,
        fileName: () => '[name].js',
        formats: [esmodule ? 'es' : 'cjs'],
      },

      /*
       * Kaynak haritası üretilmez. Kaynak haritaları, paketlenmiş kodun
       * okunmasını ve kaynak dosyalarla eşleştirilmesini kolaylaştırabilir.
       */
      sourcemap: false,

      /*
       * Üretilen JavaScript küçültülür. Bu güvenlik garantisi değildir,
       * ancak paket içindeki kodun doğrudan okunmasını zorlaştırır.
       */
      minify: 'esbuild',

      assetsInlineLimit: Number.MAX_SAFE_INTEGER,
    },

    publicDir: './resources/public',

    plugins: [
      pluginHotRestart('restart'),
      native({ forceCopyIfUnbuilt: true, webpack: {} }),
    ],

    define,

    resolve: {
      mainFields: ['module', 'jsnext:main', 'jsnext'],
    },
  };

  return mergeConfig(getBuildConfig(forgeEnv), config);
});