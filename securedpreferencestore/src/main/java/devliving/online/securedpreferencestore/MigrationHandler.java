package devliving.online.securedpreferencestore;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;

import java.io.File;
import java.util.Map;

abstract class MigrationHandler {

    public abstract void migrate(Context ctx, SharedPreferences prefsToMigrate) throws MigrationFailedException;

    protected SharedPreferences movePrefs(Context ctx, String from, String to) {
        SharedPreferences rootPrefs = ctx.getSharedPreferences(from, Context.MODE_PRIVATE);
        SharedPreferences targetPrefs = ctx.getSharedPreferences(to, Context.MODE_PRIVATE);

        SharedPreferences.Editor targetEditor = targetPrefs.edit();
        Map<String, ?> allOld = rootPrefs.getAll();
        for (Map.Entry<String, ?> x : allOld.entrySet()) {
            if(x.getValue() == null) continue;

            if      (x.getValue().getClass().equals(Boolean.class)) targetEditor.putBoolean(x.getKey(), (Boolean)x.getValue());
            else if (x.getValue().getClass().equals(Float.class))   targetEditor.putFloat(x.getKey(),   (Float)x.getValue());
            else if (x.getValue().getClass().equals(Integer.class)) targetEditor.putInt(x.getKey(),     (Integer)x.getValue());
            else if (x.getValue().getClass().equals(Long.class))    targetEditor.putLong(x.getKey(),    (Long)x.getValue());
            else if (x.getValue().getClass().equals(String.class))  targetEditor.putString(x.getKey(),  (String)x.getValue());
        }
        targetEditor.commit();
        cleanupPref(ctx, from);

        return targetPrefs;
    }

    protected void cleanupPref(Context ctx, String storeName) {
        SharedPreferences prefs = ctx.getSharedPreferences(storeName, Context.MODE_PRIVATE);
        if(prefs.getAll().size() > 0)
            prefs.edit().clear().commit();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            ctx.deleteSharedPreferences(storeName);
        } else {
            try {
                new File(ctx.getCacheDir().getParent() + "/shared_prefs/" + storeName + ".xml").delete();
            } catch(Exception e) {
                Logger.w("Unable to remove store file completely");
            }
        }
    }

    public class MigrationFailedException extends Exception {
        MigrationFailedException(String message) {
            super(message);
        }
    }
}
