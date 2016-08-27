package devliving.online.securedpreferencestore;

import android.annotation.TargetApi;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 * Created by user on 8/21/16.
 */
public class EncryptionManager {
    final int RSA_BIT_LENGTH = 2048;
    final int AES_BIT_LENGTH = 256;
    final int MAC_BIT_LENGTH = 256;
    final int GCM_TAG_LENGTH = 128;

    final String DEFAULT_CHARSET = "UTF-8";

    final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    final String SSL_PROVIDER = "AndroidOpenSSL";
    final String BOUNCY_CASTLE_PROVIDER = "BC";

    final String RSA_KEY_ALIAS = "sps_rsa_key";
    final String AES_KEY_ALIAS = "sps_aes_key";
    final String MAC_KEY_ALIAS = "sps_mac_key";

    final String DELIMITER = "]";

    final String RSA_CIPHER = KeyProperties.KEY_ALGORITHM_RSA + "/" +
            KeyProperties.BLOCK_MODE_ECB + "/" +
            KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1;
    final String AES_CIPHER = KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_GCM + "/" +
            KeyProperties.ENCRYPTION_PADDING_NONE;
    final String AES_CIPHER_COMPAT = KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_CBC + "/" +
            KeyProperties.ENCRYPTION_PADDING_PKCS7;
    final String MAC_CIPHER = "HmacSHA256";
    final String IS_COMPAT_MODE_KEY_ALIAS = "sps_data_in_compat";

    KeyStore mStore;
    SecretKey aesKey;
    SecretKey macKey;

    RSAPublicKey publicKey;
    RSAPrivateKey privateKey;

    boolean isCompatMode = false;

    public EncryptionManager(Context context, SharedPreferences prefStore) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException, InvalidKeyException, NoSuchPaddingException {
        String isCompatKey = getHashed(IS_COMPAT_MODE_KEY_ALIAS);
        isCompatMode = prefStore.getBoolean(isCompatKey, Build.VERSION.SDK_INT < Build.VERSION_CODES.M);

        loadKeyStore();
        generateKey(context, prefStore);
        loadKey(prefStore);
    }

    public EncryptedData encrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, NoSuchProviderException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        if (bytes != null && bytes.length > 0) {
            byte[] IV = getIV();
            if (isCompatMode)
                return encryptAESCompat(bytes, IV);
            else return encryptAES(bytes, IV);
        }

        return null;
    }

    /**
     * @param data
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public byte[] decrypt(EncryptedData data) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidMacException, NoSuchProviderException, InvalidKeyException {
        if (data != null && data.encryptedData != null) {
            if (isCompatMode)
                return decryptAESCompat(data);
            else return decryptAES(data);
        }

        return null;
    }

    /**
     * @param text
     * @return base64 encoded encrypted data
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws BadPaddingException
     */
    public String encrypt(String text) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchProviderException, BadPaddingException {
        if (text != null && text.length() > 0) {
            EncryptedData encrypted = encrypt(text.getBytes(DEFAULT_CHARSET));
            return encodeEncryptedData(encrypted);
        }

        return null;
    }

    /**
     *
     * @param text base64 encoded encrypted data
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IOException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchProviderException
     * @throws BadPaddingException
     */
    public String decrypt(String text) throws IOException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidMacException, NoSuchProviderException, InvalidAlgorithmParameterException {
        if (text != null && text.length() > 0) {
            EncryptedData encryptedData = decodeEncryptedText(text);
            byte[] decrypted = decrypt(encryptedData);

            return new String(decrypted, 0, decrypted.length, DEFAULT_CHARSET);
        }

        return null;
    }

    public String getHashed(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] result = digest.digest(text.getBytes(DEFAULT_CHARSET));

        return toHex(result);
    }

    String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();

        for (byte b : data) {
            sb.append(String.format("%02X", b));
        }

        return sb.toString();
    }

    public String base64Encode(byte[] data) {
        return Base64.encodeToString(data, Base64.NO_WRAP);
    }

    public byte[] base64Decode(String text) {
        return Base64.decode(text, Base64.NO_WRAP);
    }

    String encodeEncryptedData(EncryptedData data) {
        if (data.mac != null) {
            return base64Encode(data.IV) + DELIMITER + base64Encode(data.encryptedData) + DELIMITER + base64Encode(data.mac);
        } else {
            return base64Encode(data.IV) + DELIMITER + base64Encode(data.encryptedData);
        }
    }

    EncryptedData decodeEncryptedText(String text) {
        EncryptedData result = new EncryptedData();
        String[] parts = text.split(DELIMITER);
        result.IV = base64Decode(parts[0]);
        result.encryptedData = base64Decode(parts[1]);

        if (parts.length > 2) {
            result.mac = base64Decode(parts[2]);
        }

        return result;
    }

    void loadKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        mStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        mStore.load(null);
    }

    byte[] getIV() throws UnsupportedEncodingException {
        byte[] iv;
        if (!isCompatMode) {
            iv = new byte[12];
        } else {
            iv = new byte[16];
        }
        SecureRandom rng = new SecureRandom();
        rng.nextBytes(iv);
        return iv;
    }

    /**
     *
     * @param bytes - data to encrypt
     * @param IV - initialization vector
     * @return IV & Encrypted data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     */
    @TargetApi(Build.VERSION_CODES.KITKAT)
    EncryptedData encryptAES(byte[] bytes, byte[] IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, IV));
        EncryptedData result = new EncryptedData();
        result.IV = cipher.getIV();
        result.encryptedData = cipher.doFinal(bytes);

        return result;
    }

    /**
     *
     * @param encryptedData - IV & Encrypted data
     * @return decrypted data
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     */
    @TargetApi(Build.VERSION_CODES.KITKAT)
    byte[] decryptAES(EncryptedData encryptedData) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, encryptedData.IV));
        return cipher.doFinal(encryptedData.encryptedData);
    }

    /**
     *
     * @param bytes
     * @param IV
     * @return IV, Encrypted Data & Mac
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException
     */
    EncryptedData encryptAESCompat(byte[] bytes, byte[] IV) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        Cipher c = Cipher.getInstance(AES_CIPHER_COMPAT, BOUNCY_CASTLE_PROVIDER);
        c.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(IV));
        EncryptedData result = new EncryptedData();
        result.IV = c.getIV();
        result.encryptedData = c.doFinal(bytes);
        result.mac = computeMac(result.getDataForMacComputation());

        return result;
    }

    byte[] decryptAESCompat(EncryptedData encryptedData) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, InvalidMacException {
        if (verifyMac(encryptedData.mac, encryptedData.getDataForMacComputation())) {
            Cipher c = Cipher.getInstance(AES_CIPHER_COMPAT, BOUNCY_CASTLE_PROVIDER);
            c.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(encryptedData.IV));
            return c.doFinal(encryptedData.encryptedData);
        } else throw new InvalidMacException();
    }

    void loadKey(SharedPreferences prefStore) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        if (!isCompatMode) {
            if (mStore.containsAlias(AES_KEY_ALIAS) && mStore.entryInstanceOf(AES_KEY_ALIAS, KeyStore.SecretKeyEntry.class)) {
                KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) mStore.getEntry(AES_KEY_ALIAS, null);
                aesKey = entry.getSecretKey();
            }
        } else {
            aesKey = getFallbackAESKey(prefStore);
            macKey = getMacKey(prefStore);
        }
    }

    void generateKey(Context context, SharedPreferences prefStore) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException, IOException {
        if (!isCompatMode) {
            generateAESKey();
        } else {
            generateRSAKeys(context);
            loadRSAKeys();
            generateFallbackAESKey(prefStore);
            generateMacKey(prefStore);
        }
    }

    @TargetApi(Build.VERSION_CODES.M)
    boolean generateAESKey() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 25);

        if (!mStore.containsAlias(AES_KEY_ALIAS)) {
            KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER);

            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(AES_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setCertificateSubject(new X500Principal("CN = Secured Preference Store, O = Devliving Online"))
                    .setCertificateSerialNumber(BigInteger.ONE)
                    .setKeySize(AES_BIT_LENGTH)
                    .setKeyValidityEnd(end.getTime())
                    .setKeyValidityStart(start.getTime())
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(false) //TODO: set to true and let the Cipher generate a secured IV
                    .build();
            keyGen.init(spec);

            keyGen.generateKey();

            return true;
        }

        return false;
    }

    boolean generateFallbackAESKey(SharedPreferences prefStore) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyStoreException, NoSuchProviderException, UnrecoverableEntryException {
        String key = getHashed(AES_KEY_ALIAS);

        if (!prefStore.contains(key)) {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");

            keyGen.init(AES_BIT_LENGTH);
            SecretKey sKey = keyGen.generateKey();

            byte[] encryptedData = RSAEncrypt(sKey.getEncoded());

            String AESKey = Base64.encodeToString(encryptedData, Base64.NO_WRAP);
            boolean result = prefStore.edit().putString(key, AESKey).commit();
            String isCompatKey = getHashed(IS_COMPAT_MODE_KEY_ALIAS);
            prefStore.edit().putBoolean(isCompatKey, true).apply();
            return result;
        }

        return false;
    }

    boolean generateMacKey(SharedPreferences prefStore) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchProviderException, UnrecoverableEntryException, IOException {
        String key = getHashed(MAC_KEY_ALIAS);

        if (!prefStore.contains(key)) {
            byte[] randomBytes = new byte[MAC_BIT_LENGTH / 8];
            SecureRandom rng = new SecureRandom();
            rng.nextBytes(randomBytes);

            byte[] encryptedKey = RSAEncrypt(randomBytes);
            String macKey = base64Encode(encryptedKey);
            return prefStore.edit().putString(key, macKey).commit();
        }

        return false;
    }

    SecretKey getFallbackAESKey(SharedPreferences prefStore) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException {
        String key = getHashed(AES_KEY_ALIAS);

        String base64Value = prefStore.getString(key, null);
        if (base64Value != null) {
            byte[] encryptedData = Base64.decode(base64Value, Base64.NO_WRAP);
            byte[] keyData = RSADecrypt(encryptedData);

            return new SecretKeySpec(keyData, "AES");
        }

        return null;
    }

    SecretKey getMacKey(SharedPreferences prefStore) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException {
        String key = getHashed(MAC_KEY_ALIAS);

        String base64 = prefStore.getString(key, null);
        if (base64 != null) {
            byte[] encryptedKey = base64Decode(base64);
            byte[] keyData = RSADecrypt(encryptedKey);

            return new SecretKeySpec(keyData, MAC_CIPHER);
        }

        return null;
    }

    void loadRSAKeys() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        if (mStore.containsAlias(RSA_KEY_ALIAS) && mStore.entryInstanceOf(RSA_KEY_ALIAS, KeyStore.PrivateKeyEntry.class)) {
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) mStore.getEntry(RSA_KEY_ALIAS, null);
            publicKey = (RSAPublicKey) entry.getCertificate().getPublicKey();
            privateKey = (RSAPrivateKey) entry.getPrivateKey();
        }
    }

    void generateRSAKeys(Context context) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException {
        if (!mStore.containsAlias(RSA_KEY_ALIAS)) {
            Calendar start = Calendar.getInstance();
            Calendar end = Calendar.getInstance();
            end.add(Calendar.YEAR, 25);

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER);

            KeyPairGeneratorSpec spec;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                spec = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(RSA_KEY_ALIAS)
                        .setKeySize(RSA_BIT_LENGTH)
                        .setKeyType(KeyProperties.KEY_ALGORITHM_RSA)
                        .setEndDate(end.getTime())
                        .setStartDate(start.getTime())
                        .setSerialNumber(BigInteger.ONE)
                        .setSubject(new X500Principal("CN = Secured Preference Store, O = Devliving Online"))
                        .build();
            } else {
                spec = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(RSA_KEY_ALIAS)
                        .setEndDate(end.getTime())
                        .setStartDate(start.getTime())
                        .setSerialNumber(BigInteger.ONE)
                        .setSubject(new X500Principal("CN = Secured Preference Store, O = Devliving Online"))
                        .build();
            }

            keyGen.initialize(spec);
            keyGen.generateKeyPair();
        }
    }

    byte[] computeMac(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac HmacSha256 = Mac.getInstance(MAC_CIPHER);
        HmacSha256.init(macKey);
        return HmacSha256.doFinal(data);
    }

    boolean verifyMac(byte[] mac, byte[] data) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] actualMac = computeMac(data);

        if (actualMac.length != mac.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < actualMac.length; i++) {
            result |= actualMac[i] ^ mac[i];
        }
        return result == 0;
    }

    byte[] RSAEncrypt(byte[] bytes) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER, SSL_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
        cipherOutputStream.write(bytes);
        cipherOutputStream.close();

        return outputStream.toByteArray();
    }

    byte[] RSADecrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance(RSA_CIPHER, SSL_PROVIDER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(bytes), cipher);

        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
        }

        byte[] dbytes = new byte[values.size()];
        for (int i = 0; i < dbytes.length; i++) {
            dbytes[i] = values.get(i).byteValue();
        }

        cipherInputStream.close();
        return dbytes;
    }

    public static class EncryptedData {
        byte[] IV;
        byte[] encryptedData;
        byte[] mac;

        public EncryptedData() {
            IV = null;
            encryptedData = null;
            mac = null;
        }

        public EncryptedData(byte[] IV, byte[] encryptedData, byte[] mac) {
            this.IV = IV;
            this.encryptedData = encryptedData;
            this.mac = mac;
        }

        /**
         * @return IV + CIPHER
         */
        byte[] getDataForMacComputation() {
            byte[] combinedData = new byte[IV.length + encryptedData.length];
            System.arraycopy(IV, 0, combinedData, 0, IV.length);
            System.arraycopy(encryptedData, 0, combinedData, IV.length, encryptedData.length);

            return combinedData;
        }
    }

    public class InvalidMacException extends GeneralSecurityException {
        public InvalidMacException() {
            super("Invalid Mac, failed to verify integrity.");
        }
    }
}
