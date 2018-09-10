package devliving.online.securedpreferencestoresample;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.security.KeyStore;
import java.util.List;

import devliving.online.securedpreferencestore.DefaultRecoveryHandler;
import devliving.online.securedpreferencestore.SecuredPreferenceStore;

public class MainActivity extends AppCompatActivity {

    EditText text1, number1, date1, text2, number2;

    Button reloadButton, saveButton, imageDemoBtn;

    String TEXT_1 = "text_short", TEXT_2 = "text_long", NUMBER_1 = "number_int", NUMBER_2 = "number_float", DATE_1 = "date_text", DATE_2 = "date_long";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        text1 = (EditText) findViewById(R.id.text_value_1);
        number1 = (EditText) findViewById(R.id.number_1);
        date1 = (EditText) findViewById(R.id.date_1);

        text2 = (EditText) findViewById(R.id.text_value_2);
        number2 = (EditText) findViewById(R.id.number_2);

        reloadButton = (Button) findViewById(R.id.reload);
        saveButton = (Button) findViewById(R.id.save);
        imageDemoBtn = findViewById(R.id.tryFile);

        try {
            //not mandatory, can be null too
            String storeFileName = "securedStore";
            //not mandatory, can be null too
            String keyPrefix = "vss";
            //it's better to provide one, and you need to provide the same key each time after the first time
            byte[] seedKey = "seed".getBytes();
            SecuredPreferenceStore.init(getApplicationContext(), storeFileName, keyPrefix, seedKey, new DefaultRecoveryHandler());

            //SecuredPreferenceStore.init(getApplicationContext(), null);
            setupStore();
        } catch (Exception e) {
            // Handle error.
            e.printStackTrace();
        }

        reloadButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    reloadData();
                } catch (Exception e) {
                    Log.e("SECURED-PREFERENCE", "", e);
                    Toast.makeText(MainActivity.this, "An exception occurred, see log for details", Toast.LENGTH_SHORT).show();
                }
            }
        });

        saveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                try {
                    saveData();
                } catch (Exception e) {
                    Log.e("SECURED-PREFERENCE", "", e);
                    Toast.makeText(MainActivity.this, "An exception occurred, see log for details", Toast.LENGTH_SHORT).show();
                }
            }
        });

        imageDemoBtn.setOnClickListener(v -> {
            Intent intent = new Intent(this, FileDemoActivity.class);
            startActivity(intent);
        });
    }

    private void setupStore() {
        SecuredPreferenceStore.setRecoveryHandler(new DefaultRecoveryHandler(){
            @Override
            protected boolean recover(Exception e, KeyStore keyStore, List<String> keyAliases, SharedPreferences preferences) {
                Toast.makeText(MainActivity.this, "Encryption key got invalidated, will try to start over.", Toast.LENGTH_SHORT).show();
                return super.recover(e, keyStore, keyAliases, preferences);
            }
        });

        try {
            reloadData();
        } catch (Exception e) {
            Log.e("SECURED-PREFERENCE", "", e);
            Toast.makeText(this, "An exception occurred, see log for details", Toast.LENGTH_SHORT).show();
        }
    }

    void reloadData()  {
        SecuredPreferenceStore prefStore = SecuredPreferenceStore.getSharedInstance();

        String textShort = prefStore.getString(TEXT_1, null);
        String textLong = prefStore.getString(TEXT_2, null);
        int numberInt = prefStore.getInt(NUMBER_1, 0);
        float numberFloat = prefStore.getFloat(NUMBER_2, 0);
        String dateText = prefStore.getString(DATE_1, null);

        text1.setText(textShort);
        text2.setText(textLong);
        number1.setText(String.valueOf(numberInt));
        number2.setText(String.valueOf(numberFloat));
        date1.setText(dateText);
    }

    void saveData() {
        SecuredPreferenceStore prefStore = SecuredPreferenceStore.getSharedInstance();

        prefStore.edit().putString(TEXT_1, text1.length() > 0 ? text1.getText().toString() : null).apply();
        prefStore.edit().putString(TEXT_2, text2.length() > 0 ? text2.getText().toString() : null).apply();

        prefStore.edit().putInt(NUMBER_1, number1.length() > 0 ? Integer.parseInt(number1.getText().toString().trim()) : 0).apply();
        prefStore.edit().putFloat(NUMBER_2, number2.length() > 0 ? Float.parseFloat(number2.getText().toString().trim()) : 0).apply();

        prefStore.edit().putString(DATE_1, date1.length() > 0 ? date1.getText().toString() : null).apply();
    }
}
