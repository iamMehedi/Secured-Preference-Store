package devliving.online.securedpreferencestore;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by Mehedi on 8/21/16.
 */
public class SecuredPreferenceStore implements SharedPreferences {
    private final static int[] VERSIONS_WITH_BREAKING_CHANGES = new int[]{10}; //version code in ascending order
    final static String VERSION_KEY = "VERSION";
    private final static String DEFAULT_PREF_FILE_NAME = "SPS_file";

    private final String[] RESERVED_KEYS;

    private SharedPreferences mPrefs;
    private EncryptionManager mEncryptionManager;

    private static RecoveryHandler mRecoveryHandler;

    private static SecuredPreferenceStore mInstance;

    /**
     *
     * @param appContext application context
     * @param storeName optional name of the preference file
     * @param keyPrefix optional prefix for encryption key aliases
     * @param bitShiftingKey seed for randomization and bit shifting, enhances security on older OS versions
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws UnrecoverableEntryException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws MigrationFailedException
     */
    private SecuredPreferenceStore(@NonNull Context appContext, @Nullable String storeName, @Nullable String keyPrefix,
                                   @Nullable byte[] bitShiftingKey) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException, MigrationFailedException {
        Logger.d("Creating store instance");
        // handle migration
        String fileName = storeName != null ? storeName : DEFAULT_PREF_FILE_NAME;
        mPrefs = appContext.getSharedPreferences(fileName, Context.MODE_PRIVATE);

        int mRunningVersion = mPrefs.getInt(VERSION_KEY, 9);

        if(mRunningVersion < BuildConfig.VERSION_CODE) {
            new MigrationHelper(appContext, storeName, keyPrefix, bitShiftingKey)
                    .migrate(mRunningVersion, BuildConfig.VERSION_CODE);
        }

        mEncryptionManager = new EncryptionManager(appContext, mPrefs, keyPrefix, bitShiftingKey, new KeyStoreRecoveryNotifier() {
            @Override
            public boolean onRecoveryRequired(Exception e, KeyStore keyStore, List<String> keyAliases) {
                if (mRecoveryHandler != null)
                    return mRecoveryHandler.recover(e, keyStore, keyAliases, mPrefs);
                else throw new RuntimeException(e);
            }
        });

        RESERVED_KEYS = new String[]{VERSION_KEY, EncryptionManager.OVERRIDING_KEY_ALIAS_PREFIX_NAME,
                mEncryptionManager.IS_COMPAT_MODE_KEY_ALIAS, mEncryptionManager.MAC_KEY_ALIAS,
                mEncryptionManager.AES_KEY_ALIAS};
    }

    public static void setRecoveryHandler(RecoveryHandler recoveryHandler) {
        SecuredPreferenceStore.mRecoveryHandler = recoveryHandler;
    }

    synchronized public static SecuredPreferenceStore getSharedInstance() {
        if ( mInstance == null ) {
            throw new IllegalStateException("Must call init() before using the store");
        }

        return mInstance;
    }

    /**
     * Must be called once before using the SecuredPreferenceStore to initialize the shared instance.
     * You may call it in @code{onCreate} method of your application class or launcher activity
     *
     * @param appContext application context
     * @param storeName optional name of the preference file
     * @param keyPrefix optional prefix for encryption key aliases
     * @param bitShiftingKey seed for randomization and bit shifting, enhances security on older OS versions
     * @param recoveryHandler recovery handler to use if necessary
     *
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws UnrecoverableEntryException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     */
    public static void init(Context appContext, @Nullable String storeName, @Nullable String keyPrefix, @Nullable byte[] bitShiftingKey,
                            RecoveryHandler recoveryHandler ) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException, MigrationFailedException {

        if(mInstance != null){
            Logger.w("init called when there already is a non-null instance of the class");
            return;
        }

        setRecoveryHandler(recoveryHandler);
        mInstance = new SecuredPreferenceStore(appContext, storeName, keyPrefix, bitShiftingKey);
    }

    /**
     * @see #init(Context, String, String, byte[], RecoveryHandler)
     * @deprecated Use the full constructor for better security, specially on older OS versions
     */
    public static void init( Context appContext, RecoveryHandler recoveryHandler) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, KeyStoreException, MigrationFailedException {
        init(appContext, DEFAULT_PREF_FILE_NAME, null, null, recoveryHandler);
    }

    public EncryptionManager getEncryptionManager() {
        return mEncryptionManager;
    }

    private boolean isReservedKey(String key){
        return Arrays.asList(RESERVED_KEYS).contains(key);
    }

    private boolean isReservedHashedKey(String hashedKey) {
        for(String key : RESERVED_KEYS) {
            try {
                if(hashedKey.equals(EncryptionManager.getHashed(key))) {
                    return true;
                }
            } catch (NoSuchAlgorithmException e) {
                Logger.e(e);
            } catch (UnsupportedEncodingException e) {
                Logger.e(e);
            }
        }

        return false;
    }

    @Override
    public Map<String, Object> getAll() {
        Map<String, ?> all = mPrefs.getAll();
        Map<String, Object> dAll = new HashMap<>(all.size());

        if (all.size() > 0) {
            for (String key : all.keySet()) {
                if(key.equals(VERSION_KEY) || isReservedHashedKey(key)) continue;
                try {
                    Object value = all.get(key);
                    dAll.put(key, mEncryptionManager.decrypt((String) value));
                } catch (Exception e) {
                    Logger.e(e);
                }
            }
        }
        return dAll;
    }

    @Override
    public String getString(String key, String defValue) {
        if(!isReservedKey(key)) {
            try {
                String hashedKey = EncryptionManager.getHashed(key);
                String value = mPrefs.getString(hashedKey, null);
                if (value != null) return mEncryptionManager.decrypt(value);
            } catch (Exception e) {
                Logger.e(e);
            }
        }

        return defValue;
    }

    @Override
    public Set<String> getStringSet(String key, Set<String> defValues) {
        if(!isReservedKey(key)) {
            try {
                String hashedKey = EncryptionManager.getHashed(key);
                Set<String> eSet = mPrefs.getStringSet(hashedKey, null);

                if (eSet != null) {
                    Set<String> dSet = new HashSet<>(eSet.size());

                    for (String val : eSet) {
                        dSet.add(mEncryptionManager.decrypt(val));
                    }

                    return dSet;
                }

            } catch (Exception e) {
                Logger.e(e);
            }
        }

        return defValues;
    }

    @Override
    public int getInt(String key, int defValue) {
        String value = getString(key, null);
        if (value != null) {
            return Integer.parseInt(value);
        }
        return defValue;
    }

    @Override
    public long getLong(String key, long defValue) {
        String value = getString(key, null);
        if (value != null) {
            return Long.parseLong(value);
        }
        return defValue;
    }

    @Override
    public float getFloat(String key, float defValue) {
        String value = getString(key, null);
        if (value != null) {
            return Float.parseFloat(value);
        }
        return defValue;
    }

    @Override
    public boolean getBoolean(String key, boolean defValue) {
        String value = getString(key, null);
        if (value != null) {
            return Boolean.parseBoolean(value);
        }
        return defValue;
    }

    public byte[] getBytes(String key) {
        String val = getString(key, null);
        if (val != null) {
            return EncryptionManager.base64Decode(val);
        }

        return null;
    }

    @Override
    public boolean contains(String key) {
        try {
            String hashedKey = EncryptionManager.getHashed(key);
            return mPrefs.contains(hashedKey);
        } catch (Exception e) {
            Logger.e(e);
        }

        return false;
    }

    @Override
    public Editor edit() {
        return new Editor();
    }

    @Override
    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        if (mPrefs != null)
            mPrefs.registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
    }

    @Override
    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        if (mPrefs != null)
            mPrefs.unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
    }

    public class Editor implements SharedPreferences.Editor {
        SharedPreferences.Editor mEditor;

        public Editor() {
            mEditor = mPrefs.edit();
        }

        @Override
        public SharedPreferences.Editor putString(String key, String value) {
            if(isReservedKey(key)) {
                Logger.e("Trying to store value for a reserved key, value: " + value);
                return this;
            }

            try {
                String hashedKey = EncryptionManager.getHashed(key);
                String evalue = mEncryptionManager.encrypt(value);
                mEditor.putString(hashedKey, evalue);
            } catch (Exception e) {
                Logger.e(e);
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) {
            if(isReservedKey(key)) {
                Logger.e("Trying to store value for a reserved key, value: " + values);
                return this;
            }

            try {
                String hashedKey = EncryptionManager.getHashed(key);
                Set<String> eSet = new HashSet<String>(values.size());

                for (String val : values) {
                    eSet.add(mEncryptionManager.encrypt(val));
                }

                mEditor.putStringSet(hashedKey, eSet);
            } catch (Exception e) {
                Logger.e(e);
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String key, int value) {
            String val = Integer.toString(value);
            return putString(key, val);
        }

        @Override
        public SharedPreferences.Editor putLong(String key, long value) {
            String val = Long.toString(value);
            return putString(key, val);
        }

        @Override
        public SharedPreferences.Editor putFloat(String key, float value) {
            String val = Float.toString(value);
            return putString(key, val);
        }

        @Override
        public SharedPreferences.Editor putBoolean(String key, boolean value) {
            String val = Boolean.toString(value);
            return putString(key, val);
        }

        public SharedPreferences.Editor putBytes(String key, byte[] bytes) {
            if (bytes != null) {
                String val = EncryptionManager.base64Encode(bytes);
                return putString(key, val);
            } else return remove(key);
        }

        @Override
        public SharedPreferences.Editor remove(String key) {
            if(isReservedKey(key)) {
                Logger.e("Trying to remove value for a reserved key");
                return this;
            }

            try {
                String hashedKey = EncryptionManager.getHashed(key);
                mEditor.remove(hashedKey);
            } catch (Exception e) {
                Logger.e(e);
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            for(String key : mPrefs.getAll().keySet()) {
                if (key.equals(VERSION_KEY) || isReservedHashedKey(key)) continue;

                mEditor.remove(key);
            }

            return this;
        }

        @Override
        public boolean commit() {
            return mEditor.commit();
        }

        @Override
        public void apply() {
            mEditor.apply();
        }
    }

    public interface KeyStoreRecoveryNotifier{
        /**
         *
         * @param e
         * @param keyStore
         * @param keyAliases
         * @return true if the error could be resolved
         */
        boolean onRecoveryRequired(Exception e, KeyStore keyStore, List<String> keyAliases);
    }

    //region Migration
    private class MigrationHelper {
        String storeName, keyPrefix;
        byte[] bitShiftKey;
        Context mContext;

        public MigrationHelper(Context context, String storeName, String keyPrefix, byte[] bitShiftKey) {
            this.storeName = storeName;
            this.keyPrefix = keyPrefix;
            this.bitShiftKey = bitShiftKey;
            mContext = context;
        }

        /**
         * if storeName has changed from the default and there's data in the default file then those will be moved to the new file
         * if keyPrefix has changed from the default and there aren't any other prefix stored in the file, then new keys will be stored
         * with the new prefix and existing data will be migrated
         * @throws MigrationFailedException
         * @throws
         */
        void migrateToV10() throws MigrationFailedException {
            if(storeName == null && keyPrefix == null && bitShiftKey == null) {
                //using the defaults, so no migration needed
                return;
            }

            SharedPreferences prefToRead, prefToWrite;

            prefToRead = prefToWrite = mContext.getSharedPreferences(DEFAULT_PREF_FILE_NAME, Context.MODE_PRIVATE);
            boolean filenameChanged = false, prefixChanged = false;

            if(storeName != null && !storeName.equals(DEFAULT_PREF_FILE_NAME)) {
                prefToWrite = mContext.getSharedPreferences(storeName, Context.MODE_PRIVATE);
                filenameChanged = true;
            }

            String storedPrefix = null;

            try {
                storedPrefix = prefToWrite.getString(EncryptionManager.getHashed(EncryptionManager.OVERRIDING_KEY_ALIAS_PREFIX_NAME), null);
            } catch (NoSuchAlgorithmException e) {
                throw new MigrationFailedException("Migration to Version: 0.7.0: Failed to hash a key", e);
            } catch (UnsupportedEncodingException e) {
                throw new MigrationFailedException("Migration to Version: 0.7.0: Failed to hash a key", e);
            }

            prefixChanged = storedPrefix == null && keyPrefix != null && !keyPrefix.equals(EncryptionManager.DEFAULT_KEY_ALIAS_PREFIX);

            if((filenameChanged || prefixChanged) && prefToRead.getAll().size() > 0) {
                try {
                    EncryptionManager readCrypto = new EncryptionManager(mContext, prefToRead, null);
                    EncryptionManager writeCrypto = new EncryptionManager(mContext, prefToWrite, keyPrefix, bitShiftKey, null);

                    Map<String, ?> allData = prefToRead.getAll();

                    SharedPreferences.Editor editor = prefToWrite.edit();

                    for (Map.Entry<String, ?> entry : allData.entrySet()) {
                        String hashedKey = entry.getKey();

                        if (hashedKey.equals(EncryptionManager.getHashed(readCrypto.AES_KEY_ALIAS)) ||
                                hashedKey.equals(EncryptionManager.getHashed(readCrypto.IS_COMPAT_MODE_KEY_ALIAS)) ||
                                hashedKey.equals(EncryptionManager.getHashed(readCrypto.MAC_KEY_ALIAS))) {
                            continue;
                        }

                        if (entry.getValue() == null) continue;

                        if (entry.getValue() instanceof Set) { //string set
                            Set<String> values = (Set<String>) entry.getValue();
                            Set<String> eValues = new HashSet<>();

                            for (String value : values) {
                                String dValue = readCrypto.decrypt(value);
                                eValues.add(writeCrypto.encrypt(dValue));
                            }
                            editor.putStringSet(hashedKey, eValues);
                        } else if(entry.getValue() instanceof String) { //string
                            String dValue = readCrypto.decrypt((String) entry.getValue());
                            editor.putString(hashedKey, writeCrypto.encrypt(dValue));
                        } else {
                            Logger.e("Found a value that is not String or Set, key: " + hashedKey + ", value: " + entry.getValue());
                        }
                    }

                    if (editor.commit()) {
                        editor.putInt(VERSION_KEY, 10).apply();
                        cleanupPref(DEFAULT_PREF_FILE_NAME);
                    }
                } catch (InvalidKeyException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (UnrecoverableEntryException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (KeyStoreException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (NoSuchAlgorithmException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (NoSuchProviderException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (CertificateException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (UnsupportedEncodingException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (InvalidAlgorithmParameterException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (EncryptionManager.InvalidMacException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (IllegalBlockSizeException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (BadPaddingException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (NoSuchPaddingException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                } catch (IOException e) {
                    throw new MigrationFailedException("Migration to Version: 0.7.0: Encryption/Hashing Error", e);
                }
            }
        }

        void migrate(int fromVersion, int toVersion) throws MigrationFailedException {
            if(fromVersion >= toVersion) {
                return;
            }

            for(int version : VERSIONS_WITH_BREAKING_CHANGES) {
                if(fromVersion < version) {
                    migrate(version);
                    fromVersion = version;
                }
            }

            mPrefs.edit().putInt(VERSION_KEY, toVersion).apply();
        }

        void migrate(int toVersion) throws MigrationFailedException {
            if(toVersion == 10) {
                Logger.d("Migrating to: " + toVersion);
                migrateToV10();
            }
        }

        void cleanupPref(String storeName) {
            SharedPreferences prefs = mContext.getSharedPreferences(storeName, Context.MODE_PRIVATE);
            if(prefs.getAll().size() > 0) prefs.edit().clear().commit();

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                mContext.deleteSharedPreferences(storeName);
            } else {
                try {
                    new File(mContext.getCacheDir().getParent() + "/shared_prefs/" + storeName + ".xml").delete();
                } catch(Exception e) {
                    Logger.w("Unable to remove store file completely");
                }
            }
        }
    }

    public class MigrationFailedException extends Exception {
        public MigrationFailedException(String message, Throwable cause) {
            super(message, cause);
        }
    }
    //endregion
}
