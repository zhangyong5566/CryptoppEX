package com.example.zhang.cryptoppex.utils;


import java.util.HashMap;
import java.util.Random;

/**
 * Created by Administrator on 2018/11/22.
 */

public class CryptoppUtli {
    private static String stringTable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+-=|<>?,";

    /** */
    /**
     * 获取公钥的key
     */
    public static final String PUBLIC_KEY = "RSAPublicKey";

    /** */
    /**
     * 获取私钥的key
     */
    public static final String PRIVATE_KEY = "RSAPrivateKey";

    /** */
    /**
     * 获取seed
     */
    public static final String RSASEED = "RSASeed";

    static {
        System.loadLibrary("native-lib");
    }

    public static native String encryptByPublicKey(String data, String publicKey, String seed);

    public static native String decryptByPrivateKey(String data, String privateKey);

    public static native HashMap<String, String> genRSAKeyPair();

    public static native String encryptByAES(String data, String key);

    public static native String decryptByAES(String data, String key);

    public static native int encryptFileByAES(String filePath,String encryptPath ,String key);

    public static native int decryptFileByAES(String filePath,String decryptFilePath, String key);

    public static native int encryptVoiceByAES(String filePath,String encryptPath ,String key);

    public static native int decryptVoiceByAES(String filePath,String decryptFilePath, String key);

    /**
     * AESKey使用java随机生成
     *
     * @return
     */
    public static String genAESKeyPair() {
        Random random = new Random();
        int r = random.nextInt(10) + 10;
        byte[] bytes = stringTable.getBytes();
        byte[] b = new byte[r];
        for (int i = 0; i < r; i++) {
            b[i] = bytes[random.nextInt(stringTable.length())];

        }
        return new String(b);

    }


}
