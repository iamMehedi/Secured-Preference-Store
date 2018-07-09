package devliving.online.securedpreferencestore;

import android.app.Application;
import android.content.SharedPreferences;
import android.test.ApplicationTestCase;
import android.widget.Toast;

import org.jetbrains.annotations.TestOnly;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.List;

import javax.crypto.NoSuchPaddingException;

/**
 * <a href="http://d.android.com/tools/testing/testing_android.html">Testing Fundamentals</a>
 */
public class ApplicationTest extends ApplicationTestCase<Application> {
    public ApplicationTest() {
        super(Application.class);

        /*
        //not mandatory, can be null too
        String storeFileName = "securedStore";
        //not mandatory, can be null too
        String keyPrefix = "vss";
        //it's better to provide one, and you need to provide the same key each time after the first time
        byte[] seedKey = "SecuredSeedData".getBytes();
        try {
            SecuredPreferenceStore.init(getApplication().getApplicationContext(), storeFileName, keyPrefix, seedKey, new DefaultRecoveryHandler());
        } catch (Exception e) {
            e.printStackTrace();
        }
        */
    }
}