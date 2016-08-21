package devliving.online.securedpreferencestore;

import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

/**
 * Created by user on 8/21/16.
 */
class EncryptionManager {
    final int RSA_BIT_LENGTH = 2048;
    final int AES_BIT_LENGTH = 256;

    final String KEY_PROVIDER = "AndroidKeyStore";
    final String RSA_KEY_ALIAS = "sps_rsa_key";
    final String AES_KEY_ALIAS = "sps_aes_key";

    final String RSA_CIPHER = "RSA/ECB/PKCS1Padding";
    final String AES_CIPHER = "AES";

    KeyStore mStore;
    RSAPublicKey publicKey;
    RSAPrivateKey privateKey;

    SecretKey aesKey;

    EncryptionManager(Context context) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidAlgorithmParameterException, UnrecoverableEntryException {
        generateKey(context);

        mStore = KeyStore.getInstance(KEY_PROVIDER);
        mStore.load(null);

        loadKey();
    }

    public byte[] encrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        if (bytes != null && bytes.length > 0) {
            Cipher cipher;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                cipher = Cipher.getInstance(AES_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            } else {
                cipher = Cipher.getInstance(RSA_CIPHER);
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            }

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cOutStream = new CipherOutputStream(outputStream, cipher);
            cOutStream.write(bytes);
            cOutStream.close();

            return outputStream.toByteArray();
        }

        return null;
    }

    public byte[] decrypt(byte[] bytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        if (bytes != null && bytes.length > 0) {
            Cipher cipher;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                cipher = Cipher.getInstance(AES_CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, aesKey);
            } else {
                cipher = Cipher.getInstance(RSA_CIPHER);
                cipher.init(Cipher.DECRYPT_MODE, privateKey);
            }

            ByteArrayInputStream inputStream = new ByteArrayInputStream(bytes);
            CipherInputStream cInStream = new CipherInputStream(inputStream, cipher);

            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cInStream.read()) != -1) {
                values.add((byte) nextByte);
            }

            byte[] dbytes = new byte[values.size()];
            for (int i = 0; i < dbytes.length; i++) {
                dbytes[i] = values.get(i).byteValue();
            }

            cInStream.close();
            return dbytes;
        }

        return null;
    }

    public String encrypt(String text) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        if (text != null) {
            byte[] encrypted = encrypt(text.getBytes("UTF-8"));
            return Base64.encodeToString(encrypted, Base64.DEFAULT);
        }

        return null;
    }

    public String decrypt(String text) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        if (text != null) {
            byte[] bytes = Base64.decode(text, Base64.DEFAULT);
            byte[] decrypted = decrypt(bytes);

            return new String(decrypted, 0, decrypted.length, "UTF-8");
        }

        return null;
    }

    void loadKey() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (mStore.containsAlias(AES_KEY_ALIAS) && mStore.entryInstanceOf(AES_KEY_ALIAS, KeyStore.SecretKeyEntry.class)) {
                KeyStore.SecretKeyEntry entry = (KeyStore.SecretKeyEntry) mStore.getEntry(AES_KEY_ALIAS, null);
                aesKey = entry.getSecretKey();
            }
        } else {
            if (mStore.containsAlias(RSA_KEY_ALIAS) && mStore.entryInstanceOf(RSA_KEY_ALIAS, KeyStore.PrivateKeyEntry.class)) {
                KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) mStore.getEntry(AES_KEY_ALIAS, null);
                publicKey = (RSAPublicKey) entry.getCertificate().getPublicKey();
                privateKey = (RSAPrivateKey) entry.getPrivateKey();
            }
        }
    }

    void generateKey(Context context) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 25);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (!mStore.containsAlias(AES_KEY_ALIAS)) {
                KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
                KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(AES_KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                        .setCertificateSubject(new X500Principal("CN = Secured Preference Store, O = Devliving Online"))
                        .setCertificateSerialNumber(BigInteger.ONE)
                        .setDigests(KeyProperties.DIGEST_SHA256)
                        .setCertificateSerialNumber(BigInteger.ONE)
                        .setCertificateSubject(new X500Principal("CN = Secured Preference Store, O = Devliving Online"))
                        .setKeySize(AES_BIT_LENGTH)
                        .setKeyValidityEnd(end.getTime())
                        .setKeyValidityStart(start.getTime())
                        .build();
                keyGen.init(spec);

                keyGen.generateKey();
            }
        } else {
            if (!mStore.containsAlias(RSA_KEY_ALIAS)) {
                KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEY_PROVIDER);
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
    }
}
