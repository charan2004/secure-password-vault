package com.securevault.audit;

import com.securevault.core.CryptoUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuditService {

    private final AuditLogRepository auditLogRepository;
    private final CryptoUtils cryptoUtils;

    // Zero hash for genesis block
    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    public AuditService(AuditLogRepository auditLogRepository, CryptoUtils cryptoUtils) {
        this.auditLogRepository = auditLogRepository;
        this.cryptoUtils = cryptoUtils;
    }

    @Transactional
    public synchronized void log(UUID actorId, String action, String details) {
        // 1. Get previous log hash
        Optional<AuditLog> lastLog = auditLogRepository.findTopByOrderByIdDesc();
        String prevHash = lastLog.map(AuditLog::getIntegrityHash).orElse(GENESIS_HASH);

        // 2. Prepare current log data
        LocalDateTime now = LocalDateTime.now();
        
        // 3. Compute new hash
        // Formula: SHA256(prevHash + actorId + action + details + timestamp)
        String rawData = prevHash + actorId + action + details + now.toString();
        String newHash = cryptoUtils.toHex(cryptoUtils.sha256(rawData));

        // 4. Save
        AuditLog log = new AuditLog();
        log.setActorId(actorId);
        log.setAction(action);
        log.setDetails(details);
        log.setTimestamp(now);
        log.setIntegrityHash(newHash); // Set the computed hash

        auditLogRepository.save(log);
    }
}
