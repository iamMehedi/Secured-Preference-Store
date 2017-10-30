package devliving.online.securedpreferencestore;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

/**
 * Created by Mehedi on 8/21/16.
 */
public class SecuredPreferenceStore implements SharedPreferences {

    private final String PREF_FILE_NAME = "SPS_file";

    private SharedPreferences mPrefs;
    private EncryptionManager mEncryptionManager;

    private static RecoveryHandler mRecoveryHandler;

    private static SecuredPreferenceStore mInstance;

    private SecuredPreferenceStore(Context appContext) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {
        mPrefs = appContext.getSharedPreferences(PREF_FILE_NAME, Context.MODE_PRIVATE);

        mEncryptionManager = new EncryptionManager(appContext, mPrefs, new KeyStoreRecoveryNotifier() {
            @Override
            public boolean onRecoveryRequired(Exception e, KeyStore keyStore, List<String> keyAliases) {
                if (mRecoveryHandler != null)
                    return mRecoveryHandler.recover(e, keyStore, keyAliases, mPrefs);
                else throw new RuntimeException(e);
            }
        });
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
    public static void init( Context appContext,
                             RecoveryHandler recoveryHandler ) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException, NoSuchProviderException {

        if(mInstance != null){
            return;
        }

        setRecoveryHandler(recoveryHandler);
        mInstance = new SecuredPreferenceStore(appContext);
    }

    public EncryptionManager getEncryptionManager() {
        return mEncryptionManager;
    }

    @Override
    public Map<String, String> getAll() {
        Map<String, ?> all = mPrefs.getAll();
        Map<String, String> dAll = new HashMap<>(all.size());

        if (all.size() > 0) {
            for (String key : all.keySet()) {
                try {
                    dAll.put(key, mEncryptionManager.decrypt((String) all.get(key)));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
        return dAll;
    }

    @Override
    public String getString(String key, String defValue) {
        try {
            String hashedKey = EncryptionManager.getHashed(key);
            String value = mPrefs.getString(hashedKey, null);
            if (value != null) return mEncryptionManager.decrypt(value);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return defValue;
    }

    @Override
    public Set<String> getStringSet(String key, Set<String> defValues) {
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
            e.printStackTrace();
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
            e.printStackTrace();
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
            try {
                String hashedKey = EncryptionManager.getHashed(key);
                String evalue = mEncryptionManager.encrypt(value);
                mEditor.putString(hashedKey, evalue);
            } catch (Exception e) {
                e.printStackTrace();
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String key, Set<String> values) {
            try {
                String hashedKey = EncryptionManager.getHashed(key);
                Set<String> eSet = new HashSet<String>(values.size());

                for (String val : values) {
                    eSet.add(mEncryptionManager.encrypt(val));
                }

                mEditor.putStringSet(hashedKey, eSet);
            } catch (Exception e) {
                e.printStackTrace();
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
            try {
                String hashedKey = EncryptionManager.getHashed(key);
                mEditor.remove(hashedKey);
            } catch (Exception e) {
                e.printStackTrace();
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor clear() {
            mEditor.clear();

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
}
