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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 * Created by user on 8/21/16.
 */
class EncryptionManager {
    final int RSA_BIT_LENGTH = 2048;
    final int AES_BIT_LENGTH = 256;
    final int GCM_TAG_LENGTH = 128;

    final String FIXED_IV = "SomeRandomIV"; //TODO enable randomized IV
    final String DEFAULT_CHARSET = "UTF-8";

    final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    final String SSL_PROVIDER = "AndroidOpenSSL";
    final String BOUNCY_CASTLE_PROVIDER = "BC";

    final String RSA_KEY_ALIAS = "sps_rsa_key";
    final String AES_KEY_ALIAS = "sps_aes_key";

    final String RSA_CIPHER = KeyProperties.KEY_ALGORITHM_RSA + "/" +
            KeyProperties.BLOCK_MODE_ECB + "/" +
            KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1;
    final String AES_CIPHER = KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_GCM + "/" +
            KeyProperties.ENCRYPTION_PADDING_NONE;
    final String AES_CIPHER_COMPAT = KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_ECB + "/" +
            KeyProperties.ENCRYPTION_PADDING_PKCS7;

    KeyStore mStore;
    SecretKey aesKey;

    RSAPublicKey publicKey;
    RSAPrivateKey privateKey;

    boolean isCompatMode = false; //TODO make it work

    EncryptionManager(Context context, SharedPreferences prefStore) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException, InvalidKeyException, NoSuchPaddingException {
        loadKeyStore();
        generateKey(context, prefStore);
        loadKey(prefStore);
    }

    public byte[] encrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, NoSuchProviderException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        if (bytes != null && bytes.length > 0) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M || isCompatMode)
                return encryptAESCompat(bytes);
            else return encryptAES(bytes);
        }

        return null;
    }

    public byte[] decrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException, BadPaddingException, NoSuchProviderException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        if (bytes != null && bytes.length > 0) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M || isCompatMode)
                return decryptAESCompat(bytes);
            else return decryptAES(bytes);
        }

        return null;
    }

    public String encrypt(String text) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchProviderException, BadPaddingException {
        if (text != null && text.length() > 0) {
            byte[] encrypted = encrypt(text.getBytes("UTF-8"));
            return Base64.encodeToString(encrypted, Base64.DEFAULT);
        }

        return null;
    }

    public String decrypt(String text) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, InvalidAlgorithmParameterException, NoSuchProviderException, BadPaddingException {
        if (text != null && text.length() > 0) {
            byte[] bytes = Base64.decode(text, Base64.DEFAULT);
            byte[] decrypted = decrypt(bytes);

            return new String(decrypted, 0, decrypted.length, "UTF-8");
        }

        return null;
    }

    public String getHashed(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] result = digest.digest(text.getBytes(DEFAULT_CHARSET));

        StringBuilder sb = new StringBuilder();

        for (byte b : result) {
            sb.append(String.format("%02X", b));
        }

        return sb.toString();
    }

    void loadKeyStore() throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        mStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        mStore.load(null);
    }

    byte[] getIV() throws UnsupportedEncodingException {
        return FIXED_IV.getBytes(DEFAULT_CHARSET);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    byte[] encryptAES(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, getIV()));
        return cipher.doFinal(bytes);
    }

    @TargetApi(Build.VERSION_CODES.KITKAT)
    byte[] decryptAES(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LENGTH, getIV()));
        return cipher.doFinal(bytes);
    }

    byte[] encryptAESCompat(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance(AES_CIPHER_COMPAT, BOUNCY_CASTLE_PROVIDER);
        c.init(Cipher.ENCRYPT_MODE, aesKey);
        return c.doFinal(bytes);
    }

    byte[] decryptAESCompat(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance(AES_CIPHER_COMPAT, BOUNCY_CASTLE_PROVIDER);
        c.init(Cipher.DECRYPT_MODE, aesKey);
        return c.doFinal(bytes);
    }

    void loadKey(SharedPreferences prefStore) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidKeyException, IOException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (mStore.containsAlias(AES_KEY_ALIAS) && mStore.entryInstanceOf(AES_KEY_ALIAS, KeyStore.SecretKeyEntry.class)) {
                KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) mStore.getEntry(AES_KEY_ALIAS, null);
                aesKey = entry.getSecretKey();
            }
        } else {
            aesKey = getFallbackAESKey(prefStore);
        }
    }

    void generateKey(Context context, SharedPreferences prefStore) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, UnrecoverableEntryException, NoSuchPaddingException, InvalidKeyException, IOException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 25);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
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
                        .setRandomizedEncryptionRequired(false) //TODO change it
                        .build();
                keyGen.init(spec);

                keyGen.generateKey();
            }
        } else {
            generateRSAKeys(context);
            loadRSAKeys();
            generateFallbackAESKey(prefStore);
        }
    }

    boolean generateFallbackAESKey(SharedPreferences prefStore) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, KeyStoreException, NoSuchProviderException, UnrecoverableEntryException {
        String key = getHashed(AES_KEY_ALIAS);

        if (!prefStore.contains(key)) {
            byte[] keyData = new byte[AES_BIT_LENGTH / 4];
            SecureRandom rng = new SecureRandom();
            rng.nextBytes(keyData);

            byte[] encryptedData = RSAEncrypt(keyData);
            String AESKey = Base64.encodeToString(encryptedData, Base64.DEFAULT);
            return prefStore.edit().putString(key, AESKey).commit();
        }

        return false;
    }

    SecretKey getFallbackAESKey(SharedPreferences prefStore) throws IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException {
        String key = getHashed(AES_KEY_ALIAS);

        String base64Value = prefStore.getString(key, null);
        if (base64Value != null) {
            byte[] encryptedData = Base64.decode(base64Value, Base64.DEFAULT);
            byte[] keyData = RSADecrypt(encryptedData);

            return new SecretKeySpec(keyData, "AES");
        }

        return null;
    }

    void loadRSAKeys() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        if (mStore.containsAlias(RSA_KEY_ALIAS) && mStore.entryInstanceOf(RSA_KEY_ALIAS, KeyStore.PrivateKeyEntry.class)) {
            KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) mStore.getEntry(AES_KEY_ALIAS, null);
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
}
