package com.comp3026.ms.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import static org.junit.jupiter.api.Assertions.*;

class SymmetricEncrpytionTest {

    @org.junit.jupiter.api.Test
    void generateSymmetricAESKey() throws Exception {
        //generate s key
        SecretKey key = SymmetricEncrpytion.generateSymmetricAESKey();
        //Using data converter to convert . print hex binary ?
        System.out.println("Symmetric Encrpytion Key");
        System.out.println(DatatypeConverter.printHexBinary(key.getEncoded()));
    }

    @Test
    void myAESEncryption() throws Exception {

        SecretKey key = SymmetricEncrpytion.generateSymmetricAESKey();
        byte[] initializationVector = SymmetricEncrpytion.createInitializationVector();
        System.out.println("Symmetric Encrpytion Key");
        System.out.println(DatatypeConverter.printHexBinary(key.getEncoded()));

        String plainText = "This is some test!";
        System.out.println("Plaintext = " + plainText);

        byte[] cipherText = SymmetricEncrpytion.MyAESEncryption(plainText, key, initializationVector);
        System.out.println("Ciphertext = " + DatatypeConverter.printHexBinary(cipherText));

        String decryptedText = SymmetricEncrpytion.MyAESDecryption(cipherText,key,initializationVector);
        System.out.println("Decryptedtext = " + decryptedText);
    }
}