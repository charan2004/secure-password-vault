package com.securevault.core;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class CryptoServiceTest {

    private final CryptoUtils cryptoUtils = new CryptoUtils();
    private final Argon2Service argon2Service = new Argon2Service(cryptoUtils);
    private final AesGcmService aesGcmService = new AesGcmService(cryptoUtils);

    @Test
    public void testArgon2Hashing() {
        String password = "securePassword123";
        String hash = argon2Service.hash(password);
        System.out.println("Argon2 Hash: " + hash);

        Assertions.assertTrue(argon2Service.verify(password, hash), "Password verification failed");
        Assertions.assertFalse(argon2Service.verify("wrongPassword", hash), "Wrong password verified incorrectly");
    }

    @Test
    public void testKeyDerivation() {
        String password = "masterPassword";
        byte[] salt = cryptoUtils.generateRandomBytes(16);
        byte[] key = argon2Service.deriveKey(password, salt, 32);

        Assertions.assertEquals(32, key.length, "Derived key length incorrect");
    }

    @Test
    public void testAesGcmEncryption() {
        byte[] key = cryptoUtils.generateRandomBytes(32); // 256 bits
        String plaintext = "Secret Data Vault";

        AesGcmService.EncryptedData encrypted = aesGcmService.encrypt(key, plaintext);

        Assertions.assertNotNull(encrypted.getIv());
        Assertions.assertNotNull(encrypted.getCiphertext());
        Assertions.assertEquals(12, encrypted.getIv().length);

        String decrypted = aesGcmService.decryptToString(key, encrypted.getIv(), encrypted.getCiphertext());
        Assertions.assertEquals(plaintext, decrypted, "Decryption failed");
    }
}
