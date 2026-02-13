package com.securevault.vault;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface VaultEntryRepository extends JpaRepository<VaultEntry, UUID> {
    List<VaultEntry> findByOwnerId(UUID ownerId);

    List<VaultEntry> findAllByOrderByCreatedAtDesc();
}
