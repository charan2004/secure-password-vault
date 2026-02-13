package com.securevault.core;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Service
public class Argon2Service {

    private static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;
    private static final int ITERATIONS = 4;
    private static final int MEMORY = 65536; // 64 MB
    private static final int PARALLELISM = 2;

    private final CryptoUtils cryptoUtils;

    @Autowired
    public Argon2Service(CryptoUtils cryptoUtils) {
        this.cryptoUtils = cryptoUtils;
    }

    public String hash(String password) {
        byte[] salt = cryptoUtils.generateRandomBytes(SALT_LENGTH);
        byte[] hash = computeHash(password, salt);
        
        // Return format: saltHex:hashHex
        return cryptoUtils.toHex(salt) + ":" + cryptoUtils.toHex(hash);
    }

    public boolean verify(String password, String storedHash) {
        String[] parts = storedHash.split(":");
        if (parts.length != 2) {
            return false;
        }
        
        byte[] salt = cryptoUtils.fromHex(parts[0]);
        byte[] expectedHash = cryptoUtils.fromHex(parts[1]);
        
        byte[] actualHash = computeHash(password, salt);
        
        return Arrays.equals(expectedHash, actualHash);
    }
    
    /**
     * Derives a key from a password and salt using Argon2id.
     * Useful for KEK derivation.
     */
    public byte[] deriveKey(String password, byte[] salt, int keyLengthBytes) {
        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(salt)
                .withIterations(ITERATIONS)
                .withMemoryAsKB(MEMORY)
                .withParallelism(PARALLELISM);

        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(builder.build());

        byte[] result = new byte[keyLengthBytes];
        generator.generateBytes(password.getBytes(StandardCharsets.UTF_8), result);
        return result;
    }

    private byte[] computeHash(String password, byte[] salt) {
        return deriveKey(password, salt, HASH_LENGTH);
    }
}
