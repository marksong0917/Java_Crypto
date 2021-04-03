package com.comp3026.ms.crypto;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.xml.bind.DatatypeConverter;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

class AsymmetricEncryptionTest {

    @Test
    void generateRSAKeyPair() throws Exception {
        //Using  private key , generating a private keys using Asymmetric Encrpytion RSA
        PrivateKey privateKey = AsymmetricEncryption.generateRSAKeyPair().getPrivate();
        //Using  public key , generating a public keys using Asymmetric Encrpytion RSA
        PublicKey publicKey = AsymmetricEncryption.generateRSAKeyPair().getPublic();
        //Using data converter to convert . print hex binary ?
        System.out.println("Private Key: ");
        System.out.println(DatatypeConverter.printHexBinary(privateKey.getEncoded()));
        System.out.println("Public Key: ");
        System.out.println(DatatypeConverter.printHexBinary(publicKey.getEncoded()));
    }

    @Test
    void myRSAEncryption() throws Exception {

        PrivateKey privateKey = AsymmetricEncryption.generateRSAKeyPair().getPrivate();

        String plainText = "This is some test!";
        System.out.println("Plaintext = " + plainText);

        byte[] cipherText = AsymmetricEncryption.MyRSAEncryption(plainText,privateKey);
        System.out.println("Ciphertext = " + DatatypeConverter.printHexBinary(cipherText));

        String decryptedText = AsymmetricEncryption.MyRSADecryption(cipherText,privateKey);
        System.out.println("Decryptedtext = " + decryptedText);



    }




}