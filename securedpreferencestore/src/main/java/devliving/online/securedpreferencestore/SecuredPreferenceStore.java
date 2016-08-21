package devliving.online.securedpreferencestore;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.Nullable;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.NoSuchPaddingException;

/**
 * Created by Mehedi on 8/21/16.
 */
public class SecuredPreferenceStore implements SharedPreferences {

    final String PREF_FILE_NAME = "SPS_file";

    SharedPreferences mPrefs;
    EncryptionManager mEncryptionManager;

    static SecuredPreferenceStore mInstance;

    private SecuredPreferenceStore(Context appContext) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, UnrecoverableEntryException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, NoSuchPaddingException, InvalidKeyException {
        mPrefs = appContext.getSharedPreferences(PREF_FILE_NAME, Context.MODE_PRIVATE);

        mEncryptionManager = new EncryptionManager(appContext, mPrefs);
    }

    synchronized public static SecuredPreferenceStore getSharedInstance(Context appContext) {
        if (mInstance == null) {
            try {
                mInstance = new SecuredPreferenceStore(appContext);
            } catch (Exception e) {
                e.printStackTrace();

                throw new RuntimeException(e);
            }
        }

        return mInstance;
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

    @Nullable
    @Override
    public String getString(String s, String s1) {
        try {
            String key = mEncryptionManager.getHashed(s);
            String value = mPrefs.getString(key, null);
            if (value != null) return mEncryptionManager.decrypt(value);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @Nullable
    @Override
    public Set<String> getStringSet(String s, Set<String> set) {
        try {
            String key = mEncryptionManager.getHashed(s);
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

    @Override
    public boolean contains(String s) {
        try {
            String key = mEncryptionManager.getHashed(s);
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
                String key = mEncryptionManager.getHashed(s);
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
                String key = mEncryptionManager.getHashed(s);
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

        @Override
        public SharedPreferences.Editor remove(String s) {
            try {
                String key = mEncryptionManager.getHashed(s);
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
}
