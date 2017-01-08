package devliving.online.securedpreferencestore;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

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
        Log.d("SECURE-PREFERENCE", "Creating store instance");
        mPrefs = appContext.getSharedPreferences(PREF_FILE_NAME, Context.MODE_PRIVATE);

        mEncryptionManager = new EncryptionManager(appContext, mPrefs, new KeyStoreRecoveryNotifier() {
            @Override
            public boolean onRecoveryRequired(Exception e, KeyStore keyStore, List<String> keyAliases) {
                if(mRecoveryHandler != null) return mRecoveryHandler.recover(e, keyStore, keyAliases, mPrefs);
                else throw new RuntimeException(e);
            }
        });
    }

    public static void setRecoveryHandler(RecoveryHandler recoveryHandler) {
        SecuredPreferenceStore.mRecoveryHandler = recoveryHandler;
    }

    synchronized public static SecuredPreferenceStore getSharedInstance(Context appContext) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException, KeyStoreException {
        if (mInstance == null) {
            mInstance = new SecuredPreferenceStore(appContext);
        }

        return mInstance;
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
    public String getString(String s, String s1) {
        try {
            String key = EncryptionManager.getHashed(s);
            String value = mPrefs.getString(key, null);
            if (value != null) return mEncryptionManager.decrypt(value);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return s1;
    }

    @Override
    public Set<String> getStringSet(String s, Set<String> set) {
        try {
            String key = EncryptionManager.getHashed(s);
            Set<String> eSet = mPrefs.getStringSet(key, null);

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

        return set;
    }

    @Override
    public int getInt(String s, int i) {
        String value = getString(s, null);
        if (value != null) {
            return Integer.parseInt(value);
        }
        return i;
    }

    @Override
    public long getLong(String s, long l) {
        String value = getString(s, null);
        if (value != null) {
            return Long.parseLong(value);
        }
        return l;
    }

    @Override
    public float getFloat(String s, float v) {
        String value = getString(s, null);
        if (value != null) {
            return Float.parseFloat(value);
        }
        return v;
    }

    @Override
    public boolean getBoolean(String s, boolean b) {
        String value = getString(s, null);
        if (value != null) {
            return Boolean.parseBoolean(value);
        }
        return b;
    }

    public byte[] getBytes(String s) {
        String val = getString(s, null);
        if (val != null) {
            return EncryptionManager.base64Decode(val);
        }

        return null;
    }

    @Override
    public boolean contains(String s) {
        try {
            String key = EncryptionManager.getHashed(s);
            return mPrefs.contains(key);
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
        public SharedPreferences.Editor putString(String s, String s1) {
            try {
                String key = EncryptionManager.getHashed(s);
                String value = mEncryptionManager.encrypt(s1);
                mEditor.putString(key, value);
            } catch (Exception e) {
                e.printStackTrace();
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putStringSet(String s, Set<String> set) {
            try {
                String key = EncryptionManager.getHashed(s);
                Set<String> eSet = new HashSet<String>(set.size());

                for (String val : set) {
                    eSet.add(mEncryptionManager.encrypt(val));
                }

                mEditor.putStringSet(key, eSet);
            } catch (Exception e) {
                e.printStackTrace();
            }

            return this;
        }

        @Override
        public SharedPreferences.Editor putInt(String s, int i) {
            String val = Integer.toString(i);
            return putString(s, val);
        }

        @Override
        public SharedPreferences.Editor putLong(String s, long l) {
            String val = Long.toString(l);
            return putString(s, val);
        }

        @Override
        public SharedPreferences.Editor putFloat(String s, float v) {
            String val = Float.toString(v);
            return putString(s, val);
        }

        @Override
        public SharedPreferences.Editor putBoolean(String s, boolean b) {
            String val = Boolean.toString(b);
            return putString(s, val);
        }

        public SharedPreferences.Editor putBytes(String s, byte[] bytes) {
            if (bytes != null) {
                String val = EncryptionManager.base64Encode(bytes);
                return putString(s, val);
            } else return remove(s);
        }

        @Override
        public SharedPreferences.Editor remove(String s) {
            try {
                String key = EncryptionManager.getHashed(s);
                mEditor.remove(key);
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
