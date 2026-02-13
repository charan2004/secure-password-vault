package com.securevault.vault;

import lombok.AllArgsConstructor;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Decrypted vault entry with metadata
 */
@Data
@AllArgsConstructor
public class DecryptedVaultEntry {
    private UUID id;
    private UUID ownerId;
    private VaultData data;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
