package com.securevault.vault;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO representing the decrypted vault entry data
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class VaultData {
    private String title;
    private String username;
    private String password;
    private String notes;
}
