package devliving.online.securedpreferencestore;

import android.content.SharedPreferences;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.Collections;
import java.util.List;

/**
 * Created by Mehedi Hasan Khan (mehedi.mailing@gmail.com) on 12/31/16.
 */

public abstract class RecoveryHandler {
    protected abstract boolean recover(Exception e, KeyStore keyStore, List<String> keyAliases, SharedPreferences preferences);

    void clearKeyStore(KeyStore keyStore, List<String> aliases) throws KeyStoreException {
        if(keyStore != null && aliases != null){
            for(String alias:aliases){
                if(keyStore.containsAlias(alias)) keyStore.deleteEntry(alias);
            }
        }
    }

    void clearKeystore(KeyStore keyStore) throws KeyStoreException {
        if(keyStore != null){
            List<String> aliases = Collections.list(keyStore.aliases());
            for(String alias:aliases){
                if(keyStore.containsAlias(alias)) keyStore.deleteEntry(alias);
            }
        }
    }

    void clearPreferences(SharedPreferences preferences){
        if(preferences != null) preferences.edit().clear().apply();
    }
}
