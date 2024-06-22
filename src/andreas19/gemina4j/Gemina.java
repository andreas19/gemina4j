package andreas19.gemina4j;

import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;

/**
 * Main class of Gemina4J.
 */
public class Gemina {
    private final static SecureRandom RAND_GEN = new SecureRandom();
    private final static int SALT_LEN = 16; // bytes
    private final static int IV_LEN = 16; // bytes
    private final static int MAC_LEN = 32; // bytes
    private final static int MIN_LEN = 1 + 2 * IV_LEN + MAC_LEN;

    private Gemina() {}

    /**
     * Encrypt data using a secret key.
     *
     * @param key the secret key
     * @param data the data to encrypt
     * @param version the version
     * @return encrypted data
     * @throws GeneralSecurityException if something went wrong in a class
     *                                  in the security framework
     * @throws IllegalArgumentException if the key has the wrong length
     */
    public static byte[] encryptWithKey(byte[] key, byte[] data,
                                        Version version)
            throws GeneralSecurityException {
        checkKeySize(key, version);
        return encrypt(key, data, null, version);
    }

    /**
     * Decrypt data using a secret key.
     *
     * @param key the secret key
     * @param data the data to decrypt
     * @return decrypted data
     * @throws DecryptException if the data could not be decrypted
     * @throws GeneralSecurityException if something went wrong in a class
     *                                  in the security framework
     * @throws IllegalArgumentException if the key has the wrong length
     */
    public static byte[] decryptWithKey(byte[] key, byte[] data)
            throws DecryptException, GeneralSecurityException {
        Version version = checkDataAndVersion(data, 0);
        checkKeySize(key, version);
        return decrypt(key, data, 0, version);
    }

    /**
     * Verify encrypted data using a secret key.
     *
     * @param key the secret key
     * @param data the data to verify
     * @return true if secret key, authenticity and integrity are okay
     * @throws GeneralSecurityException if something went wrong in a class
     *                                  in the security framework
     * @throws IllegalArgumentException if the key has the wrong length
     */
    public static boolean verifyWithKey(byte[] key, byte[] data)
            throws GeneralSecurityException {
        Version version = null;
        try {
            version = checkDataAndVersion(data, 0);
        } catch (DecryptException e) {
            return false;
        }
        checkKeySize(key, version);
        return verify(key, data, 0, version);
    }

    /**
     * Encrypt data using a password.
     *
     * @param password the password
     * @param data the data to encrypt
     * @param version the version
     * @return encrypted data
     * @throws GeneralSecurityException if something went wrong in a class
     *                                  in the security framework
     */
    public static byte[] encryptWithPassword(char[] password,
                                             byte[] data, Version version)
            throws GeneralSecurityException {
        byte[] salt = RAND_GEN.generateSeed(SALT_LEN);
        return encrypt(deriveKey(password, salt, version), data, salt, version);
    }

    /**
     * Decrypt data using a password.
     *
     * @param password the password
     * @param data the data to decrypt
     * @return decrypted data
     * @throws DecryptException if the data could not be decrypted
     * @throws GeneralSecurityException if something went wrong in a class
     *                                  in the security framework
     */
    public static byte[] decryptWithPassword(char[] password, byte[] data)
            throws DecryptException, GeneralSecurityException {
        Version version = checkDataAndVersion(data, SALT_LEN);
        byte[] salt = Arrays.copyOfRange(data, 1, 1 + SALT_LEN);
        return decrypt(deriveKey(password, salt, version),
                       data, SALT_LEN, version);
    }

    /**
     * Verify encrypted data using a password.
     *
     * @param password the password
     * @param data the data to verify
     * @return true if password, authenticity and integrity are okay
     * @throws GeneralSecurityException if something went wrong in a class
     *                                  in the security framework
     */
    public static boolean verifyWithPassword(char[] password, byte[] data)
            throws GeneralSecurityException {
        Version version = null;
        try {
            version = checkDataAndVersion(data, SALT_LEN);
        } catch (DecryptException e) {
            return false;
        }
        byte[] salt = Arrays.copyOfRange(data, 1, 1 + SALT_LEN);
        return verify(deriveKey(password, salt, version),
                      data, SALT_LEN, version);
    }

    /**
     * Create a secret key.
     *
     * @param version the version
     * @return the secret key
     */
    public static byte[] createSecretKey(Version version) {
        return RAND_GEN.generateSeed(version.encKeyLen() + version.macKeyLen());
    }

    private static byte[] deriveKey(char[] password,
                                    byte[] salt, Version version)
            throws GeneralSecurityException {
        SecretKeyFactory skf =
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec ks = new PBEKeySpec(password, salt, version.iterations(),
                                    (version.encKeyLen()
                                     + version.macKeyLen()) * 8);
        SecretKey sk = skf.generateSecret(ks);
        return sk.getEncoded();
    }

    private static byte[] encrypt(byte[] key, byte[] data,
                                  byte[] salt, Version version)
            throws GeneralSecurityException {
        byte[] iv = RAND_GEN.generateSeed(IV_LEN);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, encKey(key, version),
                    new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(data);
        int salt_len = salt == null ? 0 : SALT_LEN;
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey(key, version));
        byte[] result = new byte[1 + salt_len + IV_LEN
                                 + ciphertext.length + MAC_LEN];
        result[0] = version.versionByte();
        mac.update(version.versionByte());
        if (salt != null) {
            System.arraycopy(salt, 0, result, 1, SALT_LEN);
            mac.update(salt);
        }
        System.arraycopy(iv, 0, result, 1 + salt_len, IV_LEN);
        mac.update(iv);
        System.arraycopy(ciphertext, 0, result,
                         1 + salt_len + IV_LEN, ciphertext.length);
        mac.update(ciphertext);
        byte[] mac_ar = mac.doFinal();
        System.arraycopy(mac_ar, 0, result, result.length - MAC_LEN,
                         mac_ar.length);
        return result;
    }

    private static byte[] decrypt(byte[] key, byte[] data,
                                  int salt_len, Version version)
            throws DecryptException, GeneralSecurityException {
        if (!verify(key, data, salt_len, version)) {
            throw new DecryptException("signature could not be verified");
        }
        byte[] iv = Arrays.copyOfRange(data, 1 + salt_len,
                                       1 + salt_len + IV_LEN);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, encKey(key, version),
                    new IvParameterSpec(iv));
        return cipher.doFinal(Arrays.copyOfRange(data, 1 + salt_len + IV_LEN,
                                                 data.length - MAC_LEN));
    }

    private static boolean verify(byte[] key, byte[] data,
                                  int salt_len, Version version)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey(key, version));
        byte[] result = mac.doFinal(Arrays.copyOfRange(data, 0,
                                    data.length - MAC_LEN));
        return Arrays.equals(Arrays.copyOfRange(data, data.length - MAC_LEN,
                             data.length), result);
    }

    private static Version checkDataAndVersion(byte[] data, int salt_len)
            throws DecryptException {
        Version version = null;
        if (data.length >= MIN_LEN + salt_len) {
            version = Version.find(data[0]);
        }
        if (version == null) {
            throw new DecryptException("unknown version or not enough data");
        }
        return version;
    }

    private static void checkKeySize(byte[] key, Version version) {
        if (key.length != version.encKeyLen() + version.macKeyLen()) {
            throw new IllegalArgumentException("incorrect secret key size");
        }
    }

    private static Key encKey(byte[] key, Version version) {
        return new SecretKeySpec(Arrays.copyOfRange(key, 0,
                                                    version.encKeyLen()),
                                                    "AES");
    }

    private static Key macKey(byte[] key, Version version) {
        return new SecretKeySpec(Arrays.copyOfRange(key, version.encKeyLen(),
                                                    key.length), "HmacSHA256");
    }
}
