#include <cryptopp/randpool.h>
#include <cryptopp/rsa.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <iostream>
#include "bench.h"
#include "crypt.h"
#include <string.h>
#include <jni.h>


NAMESPACE_BEGIN(CryptoPP)
    NAMESPACE_BEGIN(Test)
        using namespace std;
        using namespace CryptoPP;

        RandomPool &GlobalRNG();

//------------------------
// 函数声明  
//------------------------
        void GenerateRSAKey_string(unsigned int keyLength, unsigned char *privKey, int &nprivKeyLen,
                                   unsigned char *pubKey, int &npubKeyLen, const char *seed);

        void
        GenerateRSAKey(unsigned int keyLength, const char *privFilename, const char *pubFilename,
                       const char *seed);

        string RSAEncryptString(const char *pubFilename, const char *seed, const char *message);

        string RSADecryptString(const char *privFilename, const char *ciphertext);

        jstring ctojstring(JNIEnv *env, const char *tmpstr);

        void throwByName(JNIEnv *env, const char *name, const char *msg);


        std::string HexToBase64(unsigned char *pszData, int nDataLen) {
            std::string strValue;
            HexEncoder encoder;
            encoder.Put(pszData, nDataLen);
            encoder.MessageEnd();
            strValue.resize(static_cast<size_t>(encoder.MaxRetrievable()));
            encoder.Get(reinterpret_cast<byte *>(&strValue[0]), strValue.size());
            return strValue;
        }

        void Base64ToHex(std::string inStrHex, std::string &outStrHex) {
            std::string decodedKey;
            StringSource(inStrHex, true, new HexDecoder(new StringSink(decodedKey)));
            outStrHex.resize(decodedKey.size());
            memcpy(&outStrHex[0], &decodedKey[0], decodedKey.size());
        }

        std::string
        RSADecrypt(const unsigned char *pszPrivKey, int &nprivKeyLen, const char *ciphertext);

        std::string RSAEncrypt(const unsigned char *pubKey, int &npubKeyLen, const char *seed,
                               const char *message);

        std::string
        RSAEncryptString(const char *pubFilename, const char *seed, const char *message);

        SecByteBlock HexDecodeString(const char *hex);

        SecByteBlock HexDecodeString(const char *hex) {
            StringSource ss(hex, true, new HexDecoder);
            SecByteBlock result((size_t) ss.MaxRetrievable());
            ss.Get(result, result.size());
            return result;
        }

        std::string RSAEncrypt(const unsigned char *pubKey, int &npubKeyLen, const char *seed,
                               const char *message) {
            std::string strPubKey;
            strPubKey.resize(npubKeyLen);
            memcpy(&strPubKey[0], pubKey, npubKeyLen);

            StringSource ss(strPubKey, true);

            RSA::PublicKey publicKey;
            publicKey.Load(ss);

            RSAES_OAEP_SHA_Encryptor pub(publicKey);


            RandomPool randPool;
            randPool.IncorporateEntropy((byte *) seed, strlen(seed));

            std::string result;
            StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(
                    new StringSink(result))));
            return result;
        }

        std::string
        RSADecrypt(const unsigned char *pszPrivKey, int &nprivKeyLen, const char *ciphertext) {
            std::string strPrivKey;
            strPrivKey.resize(nprivKeyLen);
            memcpy(&strPrivKey[0], pszPrivKey, nprivKeyLen);

            StringSource ss(strPrivKey, true);

            RSA::PrivateKey privKey;
            privKey.Load(ss);

            RSAES_OAEP_SHA_Decryptor priv(privKey);

            std::string result;
            StringSource(ciphertext, true, new HexDecoder(
                    new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));

            return result;
        }

        //------------------------
//生成 RSA 密钥对  
//------------------------
        void GenerateRSAKey_string(unsigned int keyLength, unsigned char *privKey, int &nprivKeyLen,
                                   unsigned char *pubKey, int &npubKeyLen, const char *seed) {
            RandomPool randPool;
            randPool.IncorporateEntropy((byte *) seed, strlen(seed));

            RSAES_OAEP_SHA_Decryptor priv(randPool, keyLength);
            std::string result;
            HexEncoder privFile(new StringSink(result));
            priv.AccessMaterial().Save(privFile);
            privFile.MessageEnd();
            std::string sprki;
            StringSink ss(sprki);
            priv.AccessMaterial().Save(ss);
            memcpy(privKey, (unsigned char *) sprki.c_str(), sprki.length());
            privKey[sprki.length()] = '\0';
            nprivKeyLen = sprki.length();


            std::string resultPub;
            RSAES_OAEP_SHA_Encryptor pub(priv);
            HexEncoder pubFile(new StringSink(resultPub));
            pub.AccessMaterial().Save(pubFile);
            pubFile.MessageEnd();
            std::string sppki;
            StringSink ssp(sppki);
            pub.AccessMaterial().Save(ssp);
            memcpy(pubKey, (unsigned char *) sppki.c_str(), sppki.length());
            npubKeyLen = sppki.length();
            pubKey[npubKeyLen] = '\0';


        }

//------------------------
// RSA 加密  
//------------------------   
        string RSAEncryptString(const char *pubFilename, const char *seed, const char *message) {
            FileSource pubFile(pubFilename, true, new HexDecoder);
            RSAES_OAEP_SHA_Encryptor pub(pubFile);

            RandomPool randPool;
            randPool.IncorporateEntropy((byte *) seed, strlen(seed));

            std::string result;
            StringSource(message, true, new PK_EncryptorFilter(randPool, pub, new HexEncoder(
                    new StringSink(result))));
            return result;
        }

//------------------------   
// RSA  解密  
//------------------------   
        string RSADecryptString(const char *privFilename, const char *ciphertext) {
            FileSource privFile(privFilename, true, new HexDecoder);
            RSAES_OAEP_SHA_Decryptor priv(privFile);

            string result;
            StringSource(ciphertext, true, new HexDecoder(
                    new PK_DecryptorFilter(GlobalRNG(), priv, new StringSink(result))));
            return result;

        }


#include <android/log.h>
#include <jni.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <stdlib.h>
#include <fcntl.h>

#define LOG_TAG "Test"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

#define ZHANGFUNC(name)Java_com_example_zhang_cryptoppex_utils_##name
        /**
         * 公钥加密
         */
        extern "C"
        JNIEXPORT jstring
        JNICALL
        ZHANGFUNC(CryptoppUtli_encryptByPublicKey)(
                JNIEnv *env,
                jclass cl, jstring data, jstring publicKey, jstring seed) {

            const char *mseed = env->GetStringUTFChars(seed, 0);

            const char *pubk = env->GetStringUTFChars(publicKey, 0);
            std::string strOut;
            Base64ToHex(pubk, strOut);
            int npukLen = strOut.length();

            LOGE("公钥： %s", pubk);
            LOGE("seed： %s", mseed);
            LOGE("公钥加密，公钥长度： %d", npukLen);
            std::string ciphertext;
            char message[2048];
            strcpy(message, env->GetStringUTFChars(data, 0));
            ciphertext = RSAEncrypt((const unsigned char *) strOut.c_str(), npukLen, mseed,
                                    message);
            LOGE("加密后 %s", ciphertext.c_str());
            env->ReleaseStringUTFChars(publicKey, pubk);//释放资源
            env->ReleaseStringUTFChars(seed, mseed);//释放资源
            return env->NewStringUTF(ciphertext.c_str());

        }

        /**
         * 生成公钥私钥
         */
        extern "C"
        JNIEXPORT jobject
        JNICALL
        ZHANGFUNC(CryptoppUtli_genRSAKeyPair)(
                JNIEnv *env,
                jclass cl) {
            unsigned char privKey[2048 * 2], pubKey[2048 * 2];
            unsigned int keyLength;
            int64_t seed = time(NULL);
            keyLength = 2048;
            int npriLen = 0;
            int npukLen = 0;
            GenerateRSAKey_string(keyLength, privKey, npriLen, pubKey, npukLen, (char *) &seed);
            std::string strPubKey = HexToBase64(pubKey, npukLen);
            std::string strPriKey = HexToBase64(privKey, npriLen);
            LOGE("seed %d", seed);
            LOGE("公钥 %s", strPubKey.c_str());
            LOGE("公钥长度 %d", npukLen);
            LOGE("私钥 %s", strPriKey.c_str());
            LOGE("私钥长度 %d", npriLen);

            char ms[1024];
            sprintf(ms, "%d", seed);
            jclass java_cls_HashMap = env->FindClass("java/util/HashMap");
            jmethodID java_mid_HashMap = env->GetMethodID(java_cls_HashMap, "<init>", "()V");
            jobject java_obj_HashMap = env->NewObject(java_cls_HashMap, java_mid_HashMap, "");
            jmethodID java_mid_HashMap_put = env->GetMethodID(java_cls_HashMap, "put",
                                                              "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
            env->CallObjectMethod(java_obj_HashMap, java_mid_HashMap_put,
                                  env->NewStringUTF("RSAPublicKey"),
                                  env->NewStringUTF(strPubKey.c_str()));
            env->CallObjectMethod(java_obj_HashMap, java_mid_HashMap_put,
                                  env->NewStringUTF("RSAPrivateKey"),
                                  env->NewStringUTF(strPriKey.c_str()));
            env->CallObjectMethod(java_obj_HashMap, java_mid_HashMap_put,
                                  env->NewStringUTF("RSASeed"), env->NewStringUTF(ms));
            return java_obj_HashMap;
        }
        /**
                * 私钥解密
                */
        extern "C"
        JNIEXPORT jstring
        JNICALL
        ZHANGFUNC(CryptoppUtli_decryptByPrivateKey)(
                JNIEnv *env,
                jclass cl, jstring data, jstring privateKey) {
            const char *mdata = env->GetStringUTFChars(data, 0);
            LOGE("解密数据：%s",mdata);
            const char *pri = env->GetStringUTFChars(privateKey, 0);
            std::string strOut;
            Base64ToHex(pri, strOut);
            int npriLen = strOut.length();
            std::string decrypted = RSADecrypt((const unsigned char *) strOut.c_str(), npriLen,
                                               mdata);


            jstring result = ctojstring(env, decrypted.c_str());
            env->ReleaseStringUTFChars(data, mdata);//释放资源
            env->ReleaseStringUTFChars(privateKey, pri);//释放资源
            return result;


        }

        //转码防止中文乱码
        jstring ctojstring(JNIEnv *env, const char *tmpstr) {

            // 通过调用java的String的构造方法String(byte bytes[], String charsetName)
            // 给charsetName设置为GB2312就没问题了
            // 要执行new String(xxx)构造方法
            // 1. 先获取String的jclass
            jclass cls_string = env->FindClass("java/lang/String");
            // 2. 获取构造函数的jmethodID
            jmethodID mid_constructor = env->GetMethodID(cls_string, "<init>",
                                                         "([BLjava/lang/String;)V");
            // 3. new一个String对象
            // 创建一个jbyteArray变量
            // 字节数组里是一个个的字节byte即jbyte，
            // jbyte又是signed char的别名，说明jbyte其实就是char字符
            // 那么char* 字符串就是char字符的集合，即jbyte的集合，就是jbyteArray
            jbyteArray bytes = env->NewByteArray(strlen(tmpstr));
            env->SetByteArrayRegion(bytes, 0, strlen(tmpstr), (const jbyte *) tmpstr);

            jstring jstr_charset = env->NewStringUTF("UTF-8");
            return (jstring) env->NewObject(cls_string, mid_constructor,
                                            bytes, jstr_charset);
        }



        /**
         * aes加密
         */
        extern "C"
        JNIEXPORT jstring
        JNICALL
        ZHANGFUNC(CryptoppUtli_encryptByAES)(
                JNIEnv *env,
                jclass cl, jstring data, jstring key) {


            //--------------------------------------------------------

            const char *datas = env->GetStringUTFChars(data, 0);
            char *mkey = (char *) env->GetStringUTFChars(key, 0);
            /**
             * 在 C 语言中，字符串是以空字符做为终止标记的。所以，C 语言字符串的最后一个字符一定是 \0。
             * 请确保所有的字符串都是按照这个约定来存储的，不然程序就会因为莫名其妙的错误退出。
             * strlen 函数返回的是字符串的实际长度(所以不包括结尾的 \0 终止符)。所以为了保证有足够的空间存储所有字符，我们需要在额外 +1。
             */
            int len = env->GetStringUTFLength(data) + 1;
            string strData = datas;
            int size = aes_getsize(len);
            LOGE("加密size %d", size);
            char *pOut_str = new char[size];
            aes_encrypt(mkey, (char *) datas, len, pOut_str, size);
            LOGE("加密后 %s", pOut_str);
            string str = HexToBase64((unsigned char *) pOut_str, size);
            LOGE("加密后 %s", str.c_str());
            if (pOut_str) {
                delete[]pOut_str;
            }

            env->ReleaseStringUTFChars(data, datas);//释放资源
            env->ReleaseStringUTFChars(key, mkey);//释放资源
            return env->NewStringUTF(str.c_str());
        }

        /**
         * aes解密
         */
        extern "C"
        JNIEXPORT jstring
        JNICALL
        ZHANGFUNC(CryptoppUtli_decryptByAES)(
                JNIEnv *env,
                jclass cl, jstring data, jstring key) {
            char *datas = (char *) env->GetStringUTFChars(data, 0);
            string strOut;
            Base64ToHex(datas, strOut);
            char *mkey = (char *) env->GetStringUTFChars(key, 0);
            int len = env->GetStringUTFLength(data) + 1;      //需要+1
            int nDatalen = aes_getsize(len);
            char *pOut_str = new char[nDatalen];
            aes_decrypt(mkey, (char *) strOut.c_str(), nDatalen, pOut_str, nDatalen);
            LOGE("aesKey： %s", mkey);
            LOGE("解密后： %s", pOut_str);
            env->ReleaseStringUTFChars(data, datas);//释放资源
            env->ReleaseStringUTFChars(key, mkey);//释放资源
            return env->NewStringUTF(pOut_str);
//            jstring result = ctojstring(env, pOut_str);
//            return result;
        }



        /**
       * aes语音加密
       */
        extern "C"
        JNIEXPORT jint
        JNICALL
        ZHANGFUNC(CryptoppUtli_encryptVoiceByAES)(
                JNIEnv *env,
                jclass cl, jstring filePath, jstring cryptFilePath, jstring key) {
            const char *filename_char = env->GetStringUTFChars(filePath, 0);
            const char *crypt_fp = env->GetStringUTFChars(cryptFilePath, 0);
            const char *mkey = env->GetStringUTFChars(key, 0);

            //b字符表示操作二进制文件binary
            FILE *read_fp = fopen(filename_char, "rb");
            if (read_fp == NULL) {

                return -1;
            }
            //写的文件
            FILE *write_fp = fopen(crypt_fp, "wb");
            if (write_fp == NULL) {

                return -1;
            }
            char *buff;  //定义文件指针
            fseek(read_fp, 0, SEEK_END); //把指针移动到文件的结尾 ，获取文件长度
            int len = (int) ftell(read_fp); //获取文件长度
            buff = new char[len + 1]; //定义数组长度
            rewind(read_fp); //把指针移动到文件开头 因为我们一开始把指针移动到结尾，如果不移动回来 会出错
            fread(buff, 1, (size_t) len, read_fp); //读文件
            buff[len] = 0; //把读到的文件最后一位 写为0 要不然系统会一直寻找到0后才结束


            int dwDataSize = aes_getsize(len);
            char *pTempBuf = new char[dwDataSize];
            //加密
            int nSize = aes_encrypt((char *) mkey, buff, len, pTempBuf, dwDataSize);

            //将读到的内容写入新的文件
            fwrite(pTempBuf, sizeof(char), nSize, write_fp);
            if (pTempBuf) {
                delete[] pTempBuf;
            }
            fclose(read_fp);
            fclose(write_fp);
            env->ReleaseStringUTFChars(filePath, filename_char);//释放资源
            env->ReleaseStringUTFChars(cryptFilePath, crypt_fp);//释放资源
            env->ReleaseStringUTFChars(key, mkey);//释放资源
        }

        /**
       * aes语音解密
       */
        extern "C"
        JNIEXPORT jint
        JNICALL
        ZHANGFUNC(CryptoppUtli_decryptVoiceByAES)(
                JNIEnv *env,
                jclass cl, jstring filePath, jstring decryptFilePath, jstring key) {
            const char *filename_char = env->GetStringUTFChars(filePath, 0);
            const char *decrypt_fp = env->GetStringUTFChars(decryptFilePath, 0);
            const char *mkey = env->GetStringUTFChars(key, 0);
            //b字符表示操作二进制文件binary
            FILE *read_fp = fopen(filename_char, "rb");
            if (read_fp == NULL) {

                return -1;
            }
            //写的文件
            FILE *write_fp = fopen(decrypt_fp, "wb");
            if (write_fp == NULL) {

                return -1;
            }
            char *buff;  //定义文件指针
            fseek(read_fp, 0, SEEK_END); //把指针移动到文件的结尾 ，获取文件长度
            int len = (int) ftell(read_fp); //获取文件长度
            buff = new char[len + 1]; //定义数组长度
            rewind(read_fp); //把指针移动到文件开头 因为我们一开始把指针移动到结尾，如果不移动回来 会出错
            fread(buff, 1, (size_t) len, read_fp); //读文件
            buff[len] = 0; //把读到的文件最后一位 写为0 要不然系统会一直寻找到0后才结束
             int  dwDataSize  = aes_getsize(len);
            char *pTempBuf = new char[dwDataSize];
            int nSize = aes_decrypt((char*)mkey, buff, len, pTempBuf, len);
            char *pWriteBuf = new char[nSize];
            memcpy_s(pWriteBuf, nSize, pTempBuf, nSize);
            //将读到的内容写入新的文件
            fwrite(pWriteBuf, sizeof(char), nSize, write_fp);
            if (pWriteBuf) {
                delete[] pWriteBuf;
            }
            if (pTempBuf) {
                delete[] pTempBuf;
            }

            fclose(read_fp);
            fclose(write_fp);
            env->ReleaseStringUTFChars(filePath, filename_char);//释放资源
            env->ReleaseStringUTFChars(decryptFilePath, decrypt_fp);//释放资源
            env->ReleaseStringUTFChars(key, mkey);//释放资源
        }


        /**
        * aes文件加密
        */
        extern "C"
        JNIEXPORT jint
        JNICALL
        ZHANGFUNC(CryptoppUtli_encryptFileByAES)(
                JNIEnv *env,
                jclass cl, jstring filePath, jstring cryptFilePath, jstring key) {
            const char *filename_char = env->GetStringUTFChars(filePath, 0);
            const char *crypt_fp = env->GetStringUTFChars(cryptFilePath, 0);
            const char *mkey = env->GetStringUTFChars(key, 0);

            //b字符表示操作二进制文件binary
            FILE *read_fp = fopen(filename_char, "rb");
            if (read_fp == NULL) {

                return -1;
            }
            //写的文件
            FILE *write_fp = fopen(crypt_fp, "wb");
            if (write_fp == NULL) {

                return -1;
            }
            //缓冲区
            char buff[4096];
            int len;    //每次读取到的长度
            //读到的内容放到缓冲区，缓冲区的单位大小，缓冲区大小（一次性读4096个int的大小（4字节）的数据）
            //也就是一次读4096 X 4 字节的数据
            //返回的len是读取到的长度，小于等于4096
            while (!feof(read_fp)) {
                len = fread(buff, sizeof(char), 4096, read_fp);
                int dwDataSize = aes_getsize(len);
                char *pTempBuf = new char[dwDataSize];
                //加密
                int nSize = aes_encrypt((char *) mkey, (char *) buff, len, pTempBuf, dwDataSize);

//                fwrite(buff, sizeof(int), len, write_fp);
                //将读到的内容写入新的文件
                fwrite(pTempBuf, sizeof(char), nSize, write_fp);
                if (pTempBuf) {
                    delete[] pTempBuf;
                }

            }
            fseek(write_fp, 0, SEEK_END); //把指针移动到文件的结尾 ，获取文件长度
            int enlen = (int) ftell(write_fp); //获取文件长度
            LOGE("加密后文件大小 %d", enlen);
            fclose(read_fp);
            fclose(write_fp);
            env->ReleaseStringUTFChars(filePath, filename_char);//释放资源
            env->ReleaseStringUTFChars(cryptFilePath, crypt_fp);//释放资源
            env->ReleaseStringUTFChars(key, mkey);//释放资源
        }


        /**
         * aes文件解密
         */
        extern "C"
        JNIEXPORT jint
        JNICALL
        ZHANGFUNC(CryptoppUtli_decryptFileByAES)(
                JNIEnv *env,
                jclass cl, jstring filePath, jstring decryptFilePath, jstring key) {
            const char *filename_char = env->GetStringUTFChars(filePath, 0);
            const char *decrypt_fp = env->GetStringUTFChars(decryptFilePath, 0);
            const char *mkey = env->GetStringUTFChars(key, 0);

            //b字符表示操作二进制文件binary
            FILE *read_fp = fopen(filename_char, "rb");
            if (read_fp == NULL) {

                return -1;
            }
            //写的文件
            FILE *write_fp = fopen(decrypt_fp, "wb");
            if (write_fp == NULL) {

                return -1;
            }
            //缓冲区
            char buff[4160];
            int len;    //每次读取到的长度
            //读到的内容放到缓冲区，缓冲区的单位大小，缓冲区大小（一次性读4096个int的大小（4字节）的数据）
            //也就是一次读4096 X 4 字节的数据
            //返回的len是读取到的长度，小于等于4096
            while (!feof(read_fp)) {
                len = fread(buff, sizeof(char), 4160, read_fp);
                char *pTempBuf = new char[len];
                //解密
                int nSize = aes_decrypt((char *) mkey, (char *) buff, len, pTempBuf, len);
                char *pWriteBuf = new char[nSize];
                memcpy_s(pWriteBuf, nSize, pTempBuf, nSize);
                //将读到的内容写入新的文件
                fwrite(pWriteBuf, sizeof(char), nSize, write_fp);
                if (pWriteBuf) {
                    delete[] pWriteBuf;
                }
                if (pTempBuf) {
                    delete[] pTempBuf;
                }
            }

            fclose(read_fp);
            fclose(write_fp);
            env->ReleaseStringUTFChars(filePath, filename_char);//释放资源
            env->ReleaseStringUTFChars(decryptFilePath, decrypt_fp);//释放资源
            env->ReleaseStringUTFChars(key, mkey);//释放资源
        }


        //------------------------
// 定义全局的随机数池
//------------------------
        RandomPool &GlobalRNG() {
            static RandomPool randomPool;
            return randomPool;
        }
    NAMESPACE_END  // Test
NAMESPACE_END