package devliving.online.securedpreferencestoresample;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CalendarView;
import android.widget.EditText;

import java.util.Calendar;
import java.util.Date;

import devliving.online.securedpreferencestore.SecuredPreferenceStore;

public class MainActivity extends AppCompatActivity {

    EditText text1, number1, date1, text2, number2;

    Button reloadButton, saveButton;

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

        reloadData();

        reloadButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                reloadData();
            }
        });

        saveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                saveData();
            }
        });
    }

    void reloadData() {
        SecuredPreferenceStore prefStore = SecuredPreferenceStore.getSharedInstance(getApplicationContext());

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
        SecuredPreferenceStore prefStore = SecuredPreferenceStore.getSharedInstance(getApplicationContext());

        prefStore.edit().putString(TEXT_1, text1.length() > 0 ? text1.getText().toString() : null).apply();
        prefStore.edit().putString(TEXT_2, text2.length() > 0 ? text2.getText().toString() : null).apply();

        prefStore.edit().putInt(NUMBER_1, number1.length() > 0 ? Integer.parseInt(number1.getText().toString().trim()) : 0).apply();
        prefStore.edit().putFloat(NUMBER_2, number2.length() > 0 ? Float.parseFloat(number2.getText().toString().trim()) : 0).apply();

        prefStore.edit().putString(DATE_1, date1.length() > 0 ? date1.getText().toString() : null).apply();
    }
}
