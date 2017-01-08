package devliving.online.securedpreferencestore;

import android.content.SharedPreferences;
import android.widget.Toast;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.List;

/**
 * Created by Mehedi Hasan Khan (mehedi.mailing@gmail.com) on 12/31/16.
 */

public class DefaultRecoveryHandler extends RecoveryHandler {
    @Override
    protected boolean recover(Exception e, KeyStore keyStore, List<String> keyAliases, SharedPreferences preferences) {
        e.printStackTrace();

        try {
            clearKeyStore(keyStore, keyAliases);
            clearPreferences(preferences);
            return true;
        } catch (KeyStoreException e1) {
            e1.printStackTrace();
        }

        return false;
    }
}
