package com.comp3026.ms.crypto;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;

public class AsymmetricEncryption {

    public static KeyPair generateRSAKeyPair() throws Exception {
        // using secure random
        SecureRandom secureRandom = new SecureRandom();
        // using a pair key generator and instance of RSA
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        // Key size 4096
        keyPairGenerator.initialize(4096, secureRandom);
        //return
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] MyRSAEncryption(String plainText, PrivateKey privateKey)
            throws Exception {
        //using cipher to encrpyt plaintext with private key RSA
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String MyRSADecryption(byte[] cipherText, PrivateKey privateKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] plainTextBytes = cipher.doFinal(cipherText);
        return new String(plainTextBytes);
    }

}
