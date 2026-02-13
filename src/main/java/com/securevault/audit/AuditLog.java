package com.securevault.audit;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "audit_logs")
@Getter
@Setter
@NoArgsConstructor
public class AuditLog {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private UUID actorId;

    @Column(nullable = false)
    private String action;

    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(nullable = false)
    private String integrityHash;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    public AuditLog(UUID actorId, String action, String details, String integrityHash) {
        this.actorId = actorId;
        this.action = action;
        this.details = details;
        this.integrityHash = integrityHash;
        this.timestamp = LocalDateTime.now();
    }
}
