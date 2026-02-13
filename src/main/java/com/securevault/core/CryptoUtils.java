package com.securevault.core;

import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class CryptoUtils {

    private final SecureRandom secureRandom;

    public CryptoUtils() {
        this.secureRandom = new SecureRandom();
    }

    public byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public String toHex(byte[] data) {
        return Hex.toHexString(data);
    }

    public byte[] fromHex(String hex) {
        return Hex.decode(hex);
    }

    public byte[] sha256(String input) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return digest.digest(input.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not supported", e);
        }
    }
}
