package com.securevault.core;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

@Service
public class AesGcmService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 128; // 128 bits used in spec

    private final CryptoUtils cryptoUtils;

    public AesGcmService(CryptoUtils cryptoUtils) {
        this.cryptoUtils = cryptoUtils;
    }

    public EncryptedData encrypt(byte[] keyBytes, byte[] plaintext) {
        try {
            if (keyBytes.length != 32) {
                throw new IllegalArgumentException("Invalid key length. 32 bytes required for AES-256.");
            }

            byte[] iv = cryptoUtils.generateRandomBytes(GCM_IV_LENGTH);
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

            byte[] ciphertext = cipher.doFinal(plaintext);

            return new EncryptedData(iv, ciphertext);
        } catch (Exception e) {
            throw new CryptoException("Encryption failed", e);
        }
    }

    public EncryptedData encrypt(byte[] keyBytes, String plaintext) {
        return encrypt(keyBytes, plaintext.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] decrypt(byte[] keyBytes, byte[] iv, byte[] ciphertext) {
        try {
            if (keyBytes.length != 32) {
                throw new IllegalArgumentException("Invalid key length. 32 bytes required for AES-256.");
            }

            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new CryptoException("Decryption failed", e);
        }
    }

    public String decryptToString(byte[] keyBytes, byte[] iv, byte[] ciphertext) {
        return new String(decrypt(keyBytes, iv, ciphertext), StandardCharsets.UTF_8);
    }

    public static class EncryptedData {
        private final byte[] iv;
        private final byte[] ciphertext;

        public EncryptedData(byte[] iv, byte[] ciphertext) {
            this.iv = iv;
            this.ciphertext = ciphertext;
        }

        public byte[] getIv() {
            return iv;
        }

        public byte[] getCiphertext() {
            return ciphertext;
        }
    }
}
