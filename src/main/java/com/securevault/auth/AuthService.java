package com.securevault.auth;

import com.securevault.audit.AuditService;
import com.securevault.core.AesGcmService;
import com.securevault.core.Argon2Service;
import com.securevault.core.CryptoUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;

/**
 * Authentication service handling user registration and login with MFA
 */
@Service
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCKOUT_DURATION_MINUTES = 15;

    private final UserRepository userRepository;
    private final Argon2Service argon2Service;
    private final TotpService totpService;
    private final AesGcmService aesGcmService;
    private final CryptoUtils cryptoUtils;
    private final AuditService auditService;
    private final SessionManager sessionManager;

    // Master key for encrypting TOTP secrets (in production, use key management
    // service)
    private final byte[] totpEncryptionKey;

    public AuthService(UserRepository userRepository, Argon2Service argon2Service,
            TotpService totpService, AesGcmService aesGcmService,
            CryptoUtils cryptoUtils, AuditService auditService,
            SessionManager sessionManager) {
        this.userRepository = userRepository;
        this.argon2Service = argon2Service;
        this.totpService = totpService;
        this.aesGcmService = aesGcmService;
        this.cryptoUtils = cryptoUtils;
        this.auditService = auditService;
        this.sessionManager = sessionManager;

        // Generate or load encryption key for TOTP secrets
        // In production, this should be loaded from secure key storage
        this.totpEncryptionKey = cryptoUtils.generateRandomBytes(32);
    }

    @Transactional
    public RegistrationResult register(String username, String password, Role role) {
        // Check if username already exists
        if (userRepository.existsByUsername(username)) {
            return new RegistrationResult(false, "Username already exists", null, null);
        }

        // Hash password
        String passwordHash = argon2Service.hash(password);

        // Generate TOTP secret
        String totpSecret = totpService.generateSecret();

        // Encrypt TOTP secret before storing
        AesGcmService.EncryptedData encryptedTotp = aesGcmService.encrypt(totpEncryptionKey, totpSecret);
        String storedTotpSecret = cryptoUtils.toHex(encryptedTotp.getIv()) + ":" +
                cryptoUtils.toHex(encryptedTotp.getCiphertext());

        // Create user
        User user = new User(username, passwordHash, storedTotpSecret, role);
        userRepository.save(user);

        // Audit log
        auditService.log(user.getId(), "USER_REGISTERED", "New user registered: " + username);

        // Generate QR code URL
        String qrCodeUrl = totpService.getQrCodeUrl(username, totpSecret);

        return new RegistrationResult(true, "Registration successful", totpSecret, qrCodeUrl);
    }

    @Transactional
    public LoginResult login(String username, String password, String totpCode) {
        // Find user
        User user = userRepository.findByUsername(username).orElse(null);
        if (user == null) {
            auditService.log(null, "LOGIN_FAILED", "Unknown username: " + username);
            return new LoginResult(false, "Invalid credentials", null);
        }

        // Check if account is locked
        if (isAccountLocked(user)) {
            auditService.log(user.getId(), "LOGIN_FAILED", "Account locked due to too many failed attempts");
            return new LoginResult(false, "Account locked. Try again later.", null);
        }

        // Verify password
        if (!argon2Service.verify(password, user.getPasswordHash())) {
            handleFailedLogin(user);
            auditService.log(user.getId(), "LOGIN_FAILED", "Invalid password");
            return new LoginResult(false, "Invalid credentials", null);
        }

        // Decrypt TOTP secret
        String totpSecret = decryptTotpSecret(user.getTotpSecret());

        // Verify TOTP code
        if (!totpService.verifyCode(totpSecret, totpCode)) {
            handleFailedLogin(user);
            auditService.log(user.getId(), "MFA_FAILED", "Invalid TOTP code");
            return new LoginResult(false, "Invalid MFA code", null);
        }

        // Reset failed attempts on successful login
        user.setFailedLoginAttempts(0);
        user.setLastFailedLogin(null);
        userRepository.save(user);

        // Create session
        Session session = sessionManager.createSession(user);

        // Audit log
        auditService.log(user.getId(), "LOGIN_SUCCESS", "User logged in successfully");

        return new LoginResult(true, "Login successful", session);
    }

    public void logout(String sessionId) {
        sessionManager.getSession(sessionId).ifPresent(session -> {
            auditService.log(session.getUserId(), "LOGOUT", "User logged out");
            sessionManager.invalidateSession(sessionId);
        });
    }

    private String decryptTotpSecret(String storedSecret) {
        String[] parts = storedSecret.split(":");
        byte[] iv = cryptoUtils.fromHex(parts[0]);
        byte[] ciphertext = cryptoUtils.fromHex(parts[1]);
        return aesGcmService.decryptToString(totpEncryptionKey, iv, ciphertext);
    }

    private boolean isAccountLocked(User user) {
        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS && user.getLastFailedLogin() != null) {
            long minutesSinceLastFail = ChronoUnit.MINUTES.between(user.getLastFailedLogin(), LocalDateTime.now());
            return minutesSinceLastFail < LOCKOUT_DURATION_MINUTES;
        }
        return false;
    }

    private void handleFailedLogin(User user) {
        user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);
        user.setLastFailedLogin(LocalDateTime.now());
        userRepository.save(user);
    }

    public record RegistrationResult(boolean success, String message, String totpSecret, String qrCodeUrl) {
    }

    public record LoginResult(boolean success, String message, Session session) {
    }
}
