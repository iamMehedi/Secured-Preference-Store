package devliving.online.securedpreferencestore;

import android.util.Log;

public class Logger {
    private static boolean enabled = BuildConfig.DEBUG;
    private static final String TAG = "SECURED-PREFERENCE";

    public static void forceLoggingOn() {
        enabled = true;
    }

    public static void i(String message) {
        if(enabled) {
            Log.i(TAG, message);
        }
    }

    public static void d(String message) {
        if(enabled) {
            Log.d(TAG, message);
        }
    }

    public static void w(String message) {
        if(enabled) {
            Log.w(TAG, message);
        }
    }

    public static void e(String message) {
        if(enabled) {
            Log.e(TAG, message);
        }
    }

    public static void d(Exception e) {
        if(enabled) {
            Log.d(TAG, "Exception was thrown", e);
        }
    }

    public static void w(Exception e) {
        if(enabled) {
            Log.w(TAG, e);
        }
    }

    public static void e(Exception e) {
        if(enabled) {
            Log.e(TAG, "Exception was thrown", e);
        }
    }

    public static void d(String message, Exception e) {
        if(enabled) {
            Log.d(TAG, message, e);
        }
    }

    public static void w(String TAG, String message, Exception e) {
        if(enabled) {
            Log.w(TAG, message, e);
        }
    }

    public static void e(String message, Exception e) {
        if(enabled) {
            Log.e(TAG, message, e);
        }
    }
}
