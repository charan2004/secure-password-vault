package com.securevault.auth;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * TOTP Service implementing RFC 6238 (Time-Based One-Time Password)
 * Compatible with Google Authenticator, Authy, and other TOTP apps
 */
@Service
public class TotpService {

    private static final int SECRET_SIZE = 20; // 160 bits
    private static final String ALGORITHM = "HmacSHA1";
    private static final int TIME_STEP = 30; // 30 seconds
    private static final int DIGITS = 6;
    private static final String ISSUER = "SecureVault";

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generate a new TOTP secret (Base32 encoded)
     */
    public String generateSecret() {
        byte[] buffer = new byte[SECRET_SIZE];
        secureRandom.nextBytes(buffer);
        return Base32.encode(buffer);
    }

    /**
     * Generate TOTP code for current time
     */
    public String generateCode(String secret) {
        long timeIndex = System.currentTimeMillis() / 1000 / TIME_STEP;
        return generateCode(secret, timeIndex);
    }

    /**
     * Verify TOTP code with time window tolerance
     */
    public boolean verifyCode(String secret, String code) {
        long timeIndex = System.currentTimeMillis() / 1000 / TIME_STEP;

        // Check current time window and +/- 1 window for clock skew tolerance
        for (int i = -1; i <= 1; i++) {
            String expectedCode = generateCode(secret, timeIndex + i);
            if (expectedCode.equals(code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Generate QR code URL for authenticator apps
     */
    public String getQrCodeUrl(String username, String secret) {
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
                ISSUER, username, secret, ISSUER, DIGITS, TIME_STEP);
    }

    /**
     * Generate QR code image as Base64 PNG
     */
    public String generateQrCodeImage(String username, String secret) throws WriterException, IOException {
        String url = getQrCodeUrl(username, secret);
        QRCodeWriter qrCodeWriter = new QRCodeWriter();
        BitMatrix bitMatrix = qrCodeWriter.encode(url, BarcodeFormat.QR_CODE, 300, 300);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(bitMatrix, "PNG", outputStream);
        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }

    private String generateCode(String secret, long timeIndex) {
        try {
            byte[] key = Base32.decode(secret);
            byte[] data = ByteBuffer.allocate(8).putLong(timeIndex).array();

            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(key, ALGORITHM));
            byte[] hash = mac.doFinal(data);

            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % (int) Math.pow(10, DIGITS);
            return String.format("%0" + DIGITS + "d", otp);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("TOTP generation failed", e);
        }
    }

    /**
     * Simple Base32 encoder/decoder for TOTP secrets
     */
    private static class Base32 {
        private static final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        public static String encode(byte[] data) {
            StringBuilder result = new StringBuilder();
            int buffer = 0;
            int bufferLength = 0;

            for (byte b : data) {
                buffer = (buffer << 8) | (b & 0xFF);
                bufferLength += 8;

                while (bufferLength >= 5) {
                    result.append(BASE32_CHARS.charAt((buffer >> (bufferLength - 5)) & 0x1F));
                    bufferLength -= 5;
                }
            }

            if (bufferLength > 0) {
                result.append(BASE32_CHARS.charAt((buffer << (5 - bufferLength)) & 0x1F));
            }

            return result.toString();
        }

        public static byte[] decode(String encoded) {
            encoded = encoded.toUpperCase().replaceAll("[^A-Z2-7]", "");
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            int buffer = 0;
            int bufferLength = 0;

            for (char c : encoded.toCharArray()) {
                int value = BASE32_CHARS.indexOf(c);
                if (value == -1)
                    continue;

                buffer = (buffer << 5) | value;
                bufferLength += 5;

                if (bufferLength >= 8) {
                    result.write((buffer >> (bufferLength - 8)) & 0xFF);
                    bufferLength -= 8;
                }
            }

            return result.toByteArray();
        }
    }
}
