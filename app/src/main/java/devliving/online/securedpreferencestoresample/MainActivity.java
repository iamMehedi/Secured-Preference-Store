package devliving.online.securedpreferencestoresample;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.CalendarView;
import android.widget.EditText;

import devliving.online.securedpreferencestore.SecuredPreferenceStore;

public class MainActivity extends AppCompatActivity {

    EditText textKey, numberKey, dateKey, textValue, numberValue;
    CalendarView dateValue;

    Button reloadButton, saveButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        textKey = (EditText) findViewById(R.id.text_key);
        numberKey = (EditText) findViewById(R.id.number_key);
        dateKey = (EditText) findViewById(R.id.date_key);

        textValue = (EditText) findViewById(R.id.text_key);
        numberValue = (EditText) findViewById(R.id.number_value);
        dateValue = (CalendarView) findViewById(R.id.date_value);

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

        String text = prefStore.getString(textKey.getText().toString(), null);
        float number = prefStore.getFloat(numberKey.getText().toString(), -1);
        long date = prefStore.getLong(dateKey.getText().toString(), 0);

        textValue.setText(text);
        numberValue.setText(number != -1 ? String.valueOf(number) : null);
        dateValue.setDate(date);
    }

    void saveData() {
        SecuredPreferenceStore prefStore = SecuredPreferenceStore.getSharedInstance(getApplicationContext());

        if (textValue.length() > 0) {
            prefStore.edit().putString(textKey.getText().toString(), textValue.getText().toString()).apply();
        }

        if (numberValue.length() > 0) {
            float number = Float.parseFloat(numberValue.getText().toString().trim());
            prefStore.edit().putFloat(numberKey.getText().toString(), number).apply();
        }

        prefStore.edit().putLong(dateKey.getText().toString(), dateValue.getDate()).apply();
    }
}
