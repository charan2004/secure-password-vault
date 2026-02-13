package com.securevault.vault;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securevault.audit.AuditService;
import com.securevault.auth.Role;
import com.securevault.auth.Session;
import com.securevault.core.AesGcmService;
import com.securevault.core.CryptoUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Vault service with AES-256-GCM encryption and RBAC enforcement
 */
@Service
public class VaultService {

    private final VaultEntryRepository vaultEntryRepository;
    private final AesGcmService aesGcmService;
    private final AuditService auditService;
    private final ObjectMapper objectMapper;

    // Master vault encryption key (in production, use proper key management)
    private final byte[] vaultEncryptionKey;

    public VaultService(VaultEntryRepository vaultEntryRepository, AesGcmService aesGcmService,
            CryptoUtils cryptoUtils, AuditService auditService) {
        this.vaultEntryRepository = vaultEntryRepository;
        this.aesGcmService = aesGcmService;
        this.auditService = auditService;
        this.objectMapper = new ObjectMapper();

        // Generate or load vault encryption key
        this.vaultEncryptionKey = cryptoUtils.generateRandomBytes(32);
    }

    @Transactional
    public VaultOperationResult createEntry(Session session, VaultData data) {
        try {
            // Serialize vault data to JSON
            String jsonData = objectMapper.writeValueAsString(data);

            // Encrypt with AES-GCM
            AesGcmService.EncryptedData encrypted = aesGcmService.encrypt(vaultEncryptionKey, jsonData);

            // Create vault entry
            VaultEntry entry = new VaultEntry(session.getUserId(), encrypted.getCiphertext(), encrypted.getIv());
            vaultEntryRepository.save(entry);

            // Audit log
            auditService.log(session.getUserId(), "VAULT_CREATE",
                    "Created vault entry: " + data.getTitle() + " (ID: " + entry.getId() + ")");

            return new VaultOperationResult(true, "Entry created successfully", entry.getId());
        } catch (Exception e) {
            return new VaultOperationResult(false, "Failed to create entry: " + e.getMessage(), null);
        }
    }

    @Transactional(readOnly = true)
    public List<DecryptedVaultEntry> listEntries(Session session) {
        List<VaultEntry> entries;

        // RBAC: ADMIN can see all entries, others see only their own
        if (session.getRole() == Role.ADMIN) {
            entries = vaultEntryRepository.findAllByOrderByCreatedAtDesc();
            auditService.log(session.getUserId(), "VAULT_LIST_ALL", "Admin viewed all vault entries");
        } else {
            entries = vaultEntryRepository.findByOwnerId(session.getUserId());
            auditService.log(session.getUserId(), "VAULT_LIST", "User viewed their vault entries");
        }

        return entries.stream()
                .map(this::decryptEntry)
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public Optional<DecryptedVaultEntry> getEntry(Session session, UUID entryId) {
        Optional<VaultEntry> entryOpt = vaultEntryRepository.findById(entryId);

        if (entryOpt.isEmpty()) {
            return Optional.empty();
        }

        VaultEntry entry = entryOpt.get();

        // RBAC: Check if user has permission to view
        if (!canAccess(session, entry)) {
            auditService.log(session.getUserId(), "VAULT_ACCESS_DENIED",
                    "Attempted to access entry: " + entryId);
            return Optional.empty();
        }

        auditService.log(session.getUserId(), "VAULT_VIEW", "Viewed entry: " + entryId);
        return decryptEntry(entry);
    }

    @Transactional
    public VaultOperationResult updateEntry(Session session, UUID entryId, VaultData newData) {
        // RBAC: READ_ONLY cannot edit
        if (session.getRole() == Role.READ_ONLY) {
            return new VaultOperationResult(false, "Read-only users cannot edit entries", null);
        }

        Optional<VaultEntry> entryOpt = vaultEntryRepository.findById(entryId);
        if (entryOpt.isEmpty()) {
            return new VaultOperationResult(false, "Entry not found", null);
        }

        VaultEntry entry = entryOpt.get();

        // RBAC: Check ownership (non-admins can only edit their own)
        if (!canModify(session, entry)) {
            auditService.log(session.getUserId(), "VAULT_EDIT_DENIED",
                    "Attempted to edit entry: " + entryId);
            return new VaultOperationResult(false, "Permission denied", null);
        }

        try {
            // Encrypt new data
            String jsonData = objectMapper.writeValueAsString(newData);
            AesGcmService.EncryptedData encrypted = aesGcmService.encrypt(vaultEncryptionKey, jsonData);

            entry.setEncryptedData(encrypted.getCiphertext());
            entry.setIv(encrypted.getIv());
            entry.setVersion(entry.getVersion() + 1);
            vaultEntryRepository.save(entry);

            auditService.log(session.getUserId(), "VAULT_UPDATE",
                    "Updated entry: " + newData.getTitle() + " (ID: " + entryId + ")");

            return new VaultOperationResult(true, "Entry updated successfully", entryId);
        } catch (Exception e) {
            return new VaultOperationResult(false, "Failed to update entry: " + e.getMessage(), null);
        }
    }

    @Transactional
    public VaultOperationResult deleteEntry(Session session, UUID entryId) {
        // RBAC: READ_ONLY cannot delete
        if (session.getRole() == Role.READ_ONLY) {
            return new VaultOperationResult(false, "Read-only users cannot delete entries", null);
        }

        Optional<VaultEntry> entryOpt = vaultEntryRepository.findById(entryId);
        if (entryOpt.isEmpty()) {
            return new VaultOperationResult(false, "Entry not found", null);
        }

        VaultEntry entry = entryOpt.get();

        // RBAC: Check ownership
        if (!canModify(session, entry)) {
            auditService.log(session.getUserId(), "VAULT_DELETE_DENIED",
                    "Attempted to delete entry: " + entryId);
            return new VaultOperationResult(false, "Permission denied", null);
        }

        vaultEntryRepository.delete(entry);
        auditService.log(session.getUserId(), "VAULT_DELETE", "Deleted entry: " + entryId);

        return new VaultOperationResult(true, "Entry deleted successfully", entryId);
    }

    private Optional<DecryptedVaultEntry> decryptEntry(VaultEntry entry) {
        try {
            String jsonData = aesGcmService.decryptToString(vaultEncryptionKey, entry.getIv(),
                    entry.getEncryptedData());
            VaultData data = objectMapper.readValue(jsonData, VaultData.class);
            return Optional.of(new DecryptedVaultEntry(entry.getId(), entry.getOwnerId(), data,
                    entry.getCreatedAt(), entry.getUpdatedAt()));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private boolean canAccess(Session session, VaultEntry entry) {
        // ADMIN can access all
        if (session.getRole() == Role.ADMIN) {
            return true;
        }
        // Others can only access their own
        return entry.getOwnerId().equals(session.getUserId());
    }

    private boolean canModify(Session session, VaultEntry entry) {
        // ADMIN can modify all
        if (session.getRole() == Role.ADMIN) {
            return true;
        }
        // USER can modify their own
        if (session.getRole() == Role.USER) {
            return entry.getOwnerId().equals(session.getUserId());
        }
        // READ_ONLY cannot modify
        return false;
    }

    public record VaultOperationResult(boolean success, String message, UUID entryId) {
    }
}
