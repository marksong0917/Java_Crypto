package com.comp3026.ms.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class SymmetricEncrpytion {

    public static SecretKey generateSymmetricAESKey() throws Exception {

        //using secure Random
        SecureRandom secureRandom = new SecureRandom();
        //getting instance AES from new key Generator
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        //Initiz a secured random of key sized 256
        keyGenerator.init(256, secureRandom);
        //generating key with 256 key size with secure random
        return keyGenerator.generateKey();

    }

    public static byte[] createInitializationVector(){

        final byte blockSizeofAES = 16; // 16 bytes * 8 bits = 128 bits
        byte[] initializationVector = new byte[blockSizeofAES]; //init
        SecureRandom secureRandom = new SecureRandom(); // using new secure random
        secureRandom.nextBytes(initializationVector); //
        return initializationVector;
    }

    public static byte[] MyAESEncryption(String plainText, SecretKey secretKey,
                                        byte[] initializationVector)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String MyAESDecryption(byte[] cipherText, SecretKey secretKey,
                                         byte[] initializationVector)
            throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);
        byte[] plainTextBytes = cipher.doFinal(cipherText);
        return new String(plainTextBytes);
    }
}
