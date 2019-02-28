package com.example.zhang.cryptoppex;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Environment;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.example.zhang.cryptoppex.utils.CXAESUtil;
import com.example.zhang.cryptoppex.utils.CryptoppUtli;
import com.example.zhang.cryptoppex.utils.RSAUtil;

import java.io.File;
import java.lang.ref.SoftReference;
import java.security.Permission;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MainActivity extends AppCompatActivity implements CompoundButton.OnCheckedChangeListener, View.OnClickListener {

    private static final int WRITE_EXTERNAL_STORAGE = 1;
    private static final int READ_EXTERNAL_STORAGE = 2;
    private int flag = 0;
    private boolean isFile = false;
    private EditText mEt_input;
    private TextView mTv;
    private String mCry;
    private String mPubKey;
    private String mPriKey;
    private String mSeed;
    private String mAesKey;
    private RadioGroup mRg_file;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        mEt_input = findViewById(R.id.et_input);
        mTv = findViewById(R.id.tv);
        RadioButton rb_base64 = findViewById(R.id.rb_base64);
        RadioButton rb_md5 = findViewById(R.id.rb_md5);
        RadioButton rb_aes = findViewById(R.id.rb_aes);
        RadioButton rb_hex = findViewById(R.id.rb_hex);
        RadioButton rb_rsa = findViewById(R.id.rb_rsa);
        mRg_file = findViewById(R.id.rg_file);
        RadioButton rb_text = findViewById(R.id.rb_text);
        RadioButton rb_file = findViewById(R.id.rb_file);
        Button bt_encry = findViewById(R.id.bt_encry);
        Button bt_decry = findViewById(R.id.bt_decry);
        bt_encry.setOnClickListener(this);
        bt_decry.setOnClickListener(this);
        rb_base64.setOnCheckedChangeListener(this);
        rb_md5.setOnCheckedChangeListener(this);
        rb_aes.setOnCheckedChangeListener(this);
        rb_hex.setOnCheckedChangeListener(this);
        rb_rsa.setOnCheckedChangeListener(this);
        rb_text.setOnCheckedChangeListener(this);
        rb_file.setOnCheckedChangeListener(this);
        mAesKey = CryptoppUtli.genAESKeyPair();
        Log.i("Oking", mAesKey);

        //======================================================================//
        HashMap<String, String> stringStringHashMap = CryptoppUtli.genRSAKeyPair();
        mPubKey = stringStringHashMap.get(CryptoppUtli.PUBLIC_KEY);
        mPriKey = stringStringHashMap.get(CryptoppUtli.PRIVATE_KEY);
        mSeed = stringStringHashMap.get(CryptoppUtli.RSASEED);
        Log.i("Oking", mPubKey);
        Log.i("Oking", stringStringHashMap.get(CryptoppUtli.RSASEED));

        //检查版本是否大于M
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                        WRITE_EXTERNAL_STORAGE);
            } else {
                Toast.makeText(MainActivity.this, "权限已申请", Toast.LENGTH_SHORT).show();
            }

            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.READ_EXTERNAL_STORAGE},
                        READ_EXTERNAL_STORAGE);
            } else {
                Toast.makeText(MainActivity.this, "权限已申请", Toast.LENGTH_SHORT).show();
            }
        }
    }

    @Override
    public void onCheckedChanged(CompoundButton compoundButton, boolean b) {


        switch (compoundButton.getId()) {

            case R.id.rb_base64:
                if (b) {
                    mRg_file.setVisibility(View.GONE);
                    flag = 0;
                }
                break;
            case R.id.rb_md5:
                if (b) {
                    mRg_file.setVisibility(View.GONE);
                    flag = 1;
                }
                break;
            case R.id.rb_hex:
                if (b) {
                    mRg_file.setVisibility(View.GONE);
                    flag = 2;
                }
                break;
            case R.id.rb_aes:
                if (b) {
                    mRg_file.setVisibility(View.VISIBLE);
                    flag = 3;
                }
                break;
            case R.id.rb_rsa:
                if (b) {
                    isFile = false;
                    mRg_file.setVisibility(View.GONE);
                    mEt_input.setVisibility(View.VISIBLE);
                    flag = 4;
                }
                break;
            case R.id.rb_text:
                if (b) {
                    mEt_input.setVisibility(View.VISIBLE);
                    isFile = false;
                }
                break;
            case R.id.rb_file:
                if (b) {
                    mEt_input.setVisibility(View.GONE);
                    isFile = true;
                    mTv.setVisibility(View.GONE);
                }
                break;
            default:
                break;
        }


    }

    @Override
    public void onClick(View view) {


        switch (view.getId()) {
            case R.id.bt_encry:
                String trim = mEt_input.getText().toString().trim();
                if (isFile) {
                    encrypt(null);
                } else {
                    if (!TextUtils.isEmpty(trim)) {
                        encrypt(trim);

                    }
                }


                break;
            case R.id.bt_decry:
                String enData = mTv.getText().toString().trim();

                if (isFile) {
                    decrypt(null);
                } else {
                    if (!TextUtils.isEmpty(enData)) {

                        decrypt(enData);
                    }
                }

                break;
        }

    }

    private void decrypt(String enData) {

        switch (flag) {
            case 0:

                break;
            case 1:

                break;
            case 2:

                break;
            case 3:
                if (isFile) {            //文件解密
                    int status = CryptoppUtli.decryptFileByAES(getSDPath() + "/" + "test_encrypt.mp4", getSDPath() + "/" + "test_decrypt.mp4", mAesKey);
                    Toast.makeText(MainActivity.this, "文件解密状态：" + status, Toast.LENGTH_SHORT).show();
                } else {

                    byte[] decryptByAES = CryptoppUtli.decryptByAES(enData, mAesKey);
                    String s = new String(decryptByAES);
                    Log.i("Oking5", "AES解密后：" + s);
                    mTv.setText(s);


                }


                break;
            case 4:
                Log.i("Oking", "加密内容：" + enData);
                Log.i("Oking", "私钥：" + mPriKey);
                byte[] decryptByPrivateKey = CryptoppUtli.decryptByPrivateKey(enData, mPriKey);
                mCry = new String(decryptByPrivateKey);

                mTv.setText(mCry);
                break;
            default:
                break;
        }

    }

    private void encrypt(String trim) {
        switch (flag) {
            case 0:

                break;
            case 1:

                break;
            case 2:

                break;
            case 3:
                if (isFile) {            //aes文件加密
                    int status = CryptoppUtli.encryptFileByAES(getSDPath() + "/" + "test.mp4", getSDPath() + "/" + "test_encrypt.mp4", mAesKey);
                    String path = getSDPath() + "/" + "test_encrypt.mp4";
                    Log.i("Oking5", "加密后文件大小：" + new File(path).length());
                    Toast.makeText(MainActivity.this, "文件加密状态：" + status, Toast.LENGTH_SHORT).show();
                } else {
                    Log.i("Oking5", "加密内容：" + trim);
                    mCry = CryptoppUtli.encryptByAES(trim, mAesKey);

                    Log.i("Oking5", "AES加密后：" + mCry);
                    mTv.setText(mCry);
                }

                break;
            case 4:

                if (!TextUtils.isEmpty(mPubKey)) {

                    mCry = CryptoppUtli.encryptByPublicKey(trim, mPubKey, mSeed);
                    mTv.setText(mCry);
                }
                break;
            default:
                break;
        }
    }


    public String getSDPath() {
        File sdDir = null;
        boolean sdCardExist = Environment.getExternalStorageState()
                .equals(android.os.Environment.MEDIA_MOUNTED);//判断sd卡是否存在
        if (sdCardExist) {
            sdDir = Environment.getExternalStorageDirectory();//获取跟目录
        }
        return sdDir.getPath();
    }


    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {

        if (requestCode == WRITE_EXTERNAL_STORAGE) {
            if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {

                Toast.makeText(MainActivity.this, "权限已申请", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(MainActivity.this, "权限已拒绝", Toast.LENGTH_SHORT).show();
            }
        } else if (requestCode == READ_EXTERNAL_STORAGE) {

            for (int i = 0; i < grantResults.length; i++) {
                if (grantResults[i] != PackageManager.PERMISSION_GRANTED) {
                    //判断是否勾选禁止后不再询问
                    boolean showRequestPermission = ActivityCompat.shouldShowRequestPermissionRationale(MainActivity.this, permissions[i]);
                    if (showRequestPermission) {
                        Toast.makeText(MainActivity.this, "权限未申请", Toast.LENGTH_SHORT).show();
                    }
                }
            }
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }
}
