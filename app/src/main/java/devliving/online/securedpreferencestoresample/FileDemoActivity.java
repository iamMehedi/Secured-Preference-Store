package devliving.online.securedpreferencestoresample;

import android.Manifest;
import android.content.ContentResolver;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.OpenableColumns;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.webkit.MimeTypeMap;
import android.widget.Button;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Random;
import java.util.UUID;

import devliving.online.securedpreferencestore.SecuredPreferenceStore;

public class FileDemoActivity extends AppCompatActivity implements View.OnClickListener {

    final int PERM_REQ_CODE = 3;
    final int FILE_PICK_REQ = 2;

    Switch modeToggle;
    TextView inputFileText, outputFileText;
    Button chooseImageBtn, processBtn;

    boolean hasWritePermission = Build.VERSION.SDK_INT < 23;

    Uri inputUri, outputUri;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.file_demo_layout);

        modeToggle = findViewById(R.id.modeToggle);
        inputFileText = findViewById(R.id.inputFile);
        outputFileText = findViewById(R.id.outputFile);
        chooseImageBtn = findViewById(R.id.loadImage);
        processBtn = findViewById(R.id.processImage);

        updateProcessButton();
        processBtn.setEnabled(false);

        checkPermission();

        chooseImageBtn.setOnClickListener(this);
        processBtn.setOnClickListener(this);
        modeToggle.setOnCheckedChangeListener((view, isChecked) -> updateProcessButton());
    }

    void updateProcessButton() {
        String text = modeToggle.isChecked() ? "Encrypt" : "Decrypt";
        processBtn.setText(text);
    }

    void checkPermission() {
        if(Build.VERSION.SDK_INT >= 23) {
            hasWritePermission = checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
            if (!hasWritePermission) {
                requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, PERM_REQ_CODE);
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        hasWritePermission = grantResults[0] == PackageManager.PERMISSION_GRANTED;
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.loadImage:
                if(hasWritePermission) {
                    pickFile();
                } else {
                    checkPermission();
                }
                break;

            case R.id.processImage:
                processFile();
                break;
        }
    }

    void pickFile() {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        startActivityForResult(intent, FILE_PICK_REQ);
    }

    String getFileExtension(Uri uri) {
        ContentResolver contentResolver = getContentResolver();
        String extension;
        if(uri.getScheme() == ContentResolver.SCHEME_CONTENT) {
            extension = MimeTypeMap.getSingleton().getExtensionFromMimeType(contentResolver.getType(uri));
        } else {
            extension = MimeTypeMap.getFileExtensionFromUrl(Uri.fromFile(new File(uri.getPath())).toString());
        }

        return extension;
    }

    String findFileName(Uri uri) {
        String displayName = null;
        Cursor cursor = getContentResolver()
                        .query(uri, null, null, null, null, null);

        try {
            // moveToFirst() returns false if the cursor has 0 rows.  Very handy for
            // "if there's anything to look at, look at it" conditionals.
            if (cursor != null && cursor.moveToFirst()) {

                // Note it's called "Display Name".  This is
                // provider-specific, and might not necessarily be the file name.
                displayName = cursor.getString(
                        cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME));
                Log.i("FILE", "Display Name: " + displayName);
            }
        } finally {
            if(cursor != null) cursor.close();
        }

        return displayName;
    }

    void processFile() {
        if(inputUri != null) {
            processBtn.setEnabled(false);

            String fileName = findFileName(inputUri);
            if(fileName == null) {
                Toast.makeText(this, "Error: Filename could not be found", Toast.LENGTH_LONG).show();
                fileName = UUID.randomUUID().toString();
                String extension = getFileExtension(inputUri);

                if(extension == null) {
                    Toast.makeText(this, "Error: File extension could not be found", Toast.LENGTH_LONG).show();
                    return;
                } else {
                    fileName = fileName + "." + extension;
                }
            }

            String prefix = modeToggle.isChecked() ? "ENC" : "DEC";
            fileName = prefix + fileName;

            try {
                File outputFile = new File(getExternalFilesDir(null), fileName);
                BufferedInputStream fileIn = new BufferedInputStream(getContentResolver().openInputStream(inputUri));
                BufferedOutputStream fileOut = new BufferedOutputStream(new FileOutputStream(outputFile));

                if(modeToggle.isChecked()) {
                    SecuredPreferenceStore.getSharedInstance().getEncryptionManager().tryEncrypt(fileIn, fileOut);
                } else {
                    SecuredPreferenceStore.getSharedInstance().getEncryptionManager().tryDecrypt(fileIn, fileOut);
                }

                outputUri = Uri.fromFile(outputFile);
                outputFileText.setText(outputUri.getPath());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);

        if(requestCode == FILE_PICK_REQ && resultCode == RESULT_OK) {
            inputUri = data.getData();
            inputFileText.setText(inputUri.getPath());

            processBtn.setEnabled(true);
        }
    }
}
