package devliving.online.securedpreferencestore;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import java.io.IOException;
import java.lang.reflect.Type;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static devliving.online.securedpreferencestore.EncryptionManager.getHashed;
import static devliving.online.securedpreferencestore.SecuredPreferenceStore.VERSION_KEY;

public class MigrateFrom050to060 extends MigrationHandler {
    private static final String OLD_FILE_NAME = "SPS_file";
    private static final String TEMP_FILE_NAME = "gn38cnslj";
    private static final String SECONDARY_FILE_NAME = "o12nfn93";
    private static final int FROM_VERSION = 500;
    private static final int TO_VERSION = 600;

    private final String mNewStoreName;
    private final String mFallbackBitshiftString;

    private EncryptionManager mOldEncryptionManager;
    private EncryptionManager mNewEncryptionManager;
    private SharedPreferences.Editor mEditor;

    public MigrateFrom050to060(String newStoreName, String fallbackBitshiftString) {
        this.mNewStoreName = newStoreName;
        this.mFallbackBitshiftString = fallbackBitshiftString;
    }

    @SuppressLint("ApplySharedPref")
    @Override
    public void migrate(Context ctx, SharedPreferences prefsToMigrate) throws MigrationFailedException {
        if(!prefsToMigrate.contains(VERSION_KEY) && prefsToMigrate.getAll().size() != 0) {
            prefsToMigrate.edit().putInt(VERSION_KEY, FROM_VERSION).commit();
        } else if(!prefsToMigrate.contains(VERSION_KEY)) {
            prefsToMigrate.edit().putInt(VERSION_KEY, TO_VERSION).commit();
        }

        SharedPreferences targetPrefs = ctx.getSharedPreferences(mNewStoreName, Context.MODE_PRIVATE);

        if(prefsToMigrate.getInt(VERSION_KEY, FROM_VERSION) >= TO_VERSION || targetPrefs.getInt(VERSION_KEY, FROM_VERSION) >= TO_VERSION) {
            if(!OLD_FILE_NAME.equals(mNewStoreName))
                cleanupPref(ctx, OLD_FILE_NAME);
            Logger.i("Nothing to migrate to version 0.6.0. Can be initialized without.");
            return;
        }

        cleanupPref(ctx, TEMP_FILE_NAME);
        SharedPreferences newTmpPrefs = ctx.getSharedPreferences(TEMP_FILE_NAME, Context.MODE_PRIVATE);
        mEditor = newTmpPrefs.edit();

        try {
            mOldEncryptionManager = new EncryptionManager(ctx, prefsToMigrate, null);
            mNewEncryptionManager = new EncryptionManager(ctx, newTmpPrefs, null, mFallbackBitshiftString, null);

            String controlValue = mOldEncryptionManager.encrypt("CONTROL");
            prefsToMigrate.edit()
                    .putString(EncryptionManager.getHashed("CONTROL_KEY"), controlValue)
                    .commit();

            Map<String, ?> prefsToMigrateAll = prefsToMigrate.getAll();
            for (Map.Entry<String, ?> elem : prefsToMigrateAll.entrySet()) {
                String key = elem.getKey();
                Object value = elem.getValue();
                if(value == null) continue;
                Type valueType = value.getClass();


                if (key.equals(getHashed("sps_rsa_key"))
                        || key.equals(getHashed("sps_aes_key"))
                        || key.equals(getHashed("sps_mac_key")))
                    continue;
                else if (key.equals(getHashed("sps_data_in_compat")))
                    continue;
                else if (valueType.equals(String.class)) putString(key, (String) value);
                else
                    Logger.w("Did not handle value with key " + key + " and type " + valueType);
            }

            mEditor.putInt(VERSION_KEY, TO_VERSION);
            if (!mEditor.commit()) {
                throw createException("Migration failed - unable to write to new file");
            }

            String encryptedControlValue = newTmpPrefs.getString(getHashed("CONTROL_KEY"), null);
            if (encryptedControlValue == null)
                throw createException("Migration failed - data not consistent. Unable to find control key");
            String decyptedControlValue = mNewEncryptionManager.decrypt(encryptedControlValue);
            if (!decyptedControlValue.equals("CONTROL")) {
                throw createException("Migration failed - data not consistent. Expected to find control string, but found " + decyptedControlValue);
            }

            mNewEncryptionManager.makePermanentKeyAlias();

            movePrefs(ctx, OLD_FILE_NAME, SECONDARY_FILE_NAME);
            try {
                movePrefs(ctx, TEMP_FILE_NAME, mNewStoreName);
                cleanupPref(ctx, TEMP_FILE_NAME);
                cleanupPref(ctx, SECONDARY_FILE_NAME);
            } catch (Exception e) {
                try {
                    movePrefs(ctx, SECONDARY_FILE_NAME, OLD_FILE_NAME);
                } catch (Exception ex) {
                    throw createException("Migration failed - Unable to recover data");
                }
                throw createException("Migration failed - Recovered data to previous state", e);
            }
        } catch (Exception e) {
            try {
                if(!OLD_FILE_NAME.equals(mNewStoreName))
                    cleanupPref(ctx, mNewStoreName);
            } catch(Exception ex) {
                Logger.e("Unable to clean new store - this could present a problem on next run");
            }

            if(e.getClass().equals(MigrationFailedException.class)) throw (MigrationFailedException)e;
            throw createException("Migration failed - Store should still be intact", e);
        }
    }

    private void putString(String prehashedKey, String encryptedValue) throws IOException, NoSuchAlgorithmException, InvalidKeyException, UnrecoverableEntryException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, KeyStoreException, NoSuchProviderException, IllegalBlockSizeException, EncryptionManager.InvalidMacException {
        String value = mOldEncryptionManager.decrypt(encryptedValue);
        String evalue = mNewEncryptionManager.encrypt(value);
        mEditor.putString(prehashedKey, evalue);
    }

    private MigrationFailedException createException(String message) throws MigrationFailedException {
        Logger.e(message);
        throw new MigrationFailedException(message);
    }

    private MigrationFailedException createException(String message, Exception e) throws MigrationFailedException {
        Logger.e(message, e);
        throw new MigrationFailedException(message);
    }
}
