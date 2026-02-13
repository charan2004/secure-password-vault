package com.securevault.vault;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "vault_entries")
@Getter
@Setter
@NoArgsConstructor
public class VaultEntry {
    @Id
    private UUID id;

    @Column(nullable = false)
    private UUID ownerId;

    @Column(nullable = false)
    private byte[] encryptedData; // Encrypted JSON containing title, username, password, notes

    @Column(nullable = false)
    private byte[] iv; // Initialization vector for AES-GCM

    @Column
    private byte[] aad; // Additional authenticated data

    @Column(nullable = false)
    private int version = 1;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public VaultEntry(UUID ownerId, byte[] encryptedData, byte[] iv) {
        this.ownerId = ownerId;
        this.encryptedData = encryptedData;
        this.iv = iv;
    }
}
