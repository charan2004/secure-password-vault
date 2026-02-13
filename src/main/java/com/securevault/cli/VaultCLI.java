package com.securevault.cli;

import com.securevault.auth.*;
import com.securevault.vault.*;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Scanner;
import java.util.UUID;

/**
 * CLI interface for the Secure Password Vault
 */
@Component
public class VaultCLI implements CommandLineRunner {

    private final AuthService authService;
    private final VaultService vaultService;

    private Session currentSession;
    private final Scanner scanner = new Scanner(System.in);

    public VaultCLI(AuthService authService, VaultService vaultService) {
        this.authService = authService;
        this.vaultService = vaultService;
    }

    @Override
    public void run(String... args) {
        printBanner();
        mainLoop();
    }

    private void mainLoop() {
        boolean running = true;
        while (running) {
            try {
                if (currentSession == null) {
                    printUnauthenticatedMenu();
                } else {
                    printAuthenticatedMenu();
                }

                String command = scanner.nextLine().trim().toLowerCase();

                if (currentSession == null) {
                    running = handleUnauthenticatedCommand(command);
                } else {
                    running = handleAuthenticatedCommand(command);
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        }
        scanner.close();
    }

    private boolean handleUnauthenticatedCommand(String command) {
        switch (command) {
            case "register" -> handleRegister();
            case "login" -> handleLogin();
            case "exit" -> {
                System.out.println("Goodbye!");
                return false;
            }
            default -> System.out.println("Unknown command. Type 'register', 'login', or 'exit'.");
        }
        return true;
    }

    private boolean handleAuthenticatedCommand(String command) {
        switch (command) {
            case "add" -> handleAddEntry();
            case "list" -> handleListEntries();
            case "view" -> handleViewEntry();
            case "edit" -> handleEditEntry();
            case "delete" -> handleDeleteEntry();
            case "logout" -> handleLogout();
            case "exit" -> {
                handleLogout();
                System.out.println("Goodbye!");
                return false;
            }
            default -> System.out.println("Unknown command. Type 'help' for available commands.");
        }
        return true;
    }

    private void handleRegister() {
        System.out.println("\n=== User Registration ===");
        System.out.print("Username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Password: ");
        String password = scanner.nextLine().trim();

        System.out.print("Confirm Password: ");
        String confirmPassword = scanner.nextLine().trim();

        if (!password.equals(confirmPassword)) {
            System.out.println("Passwords do not match!");
            return;
        }

        if (password.length() < 8) {
            System.out.println("Password must be at least 8 characters!");
            return;
        }

        System.out.print("Role (ADMIN/USER/READ_ONLY) [default: USER]: ");
        String roleInput = scanner.nextLine().trim().toUpperCase();
        Role role = roleInput.isEmpty() ? Role.USER : Role.valueOf(roleInput);

        AuthService.RegistrationResult result = authService.register(username, password, role);

        if (result.success()) {
            System.out.println("\n✓ " + result.message());
            System.out.println("\n=== MFA Setup ===");
            System.out.println("Scan this QR code with your authenticator app:");
            System.out.println(result.qrCodeUrl());
            System.out.println("\nOr manually enter this secret:");
            System.out.println(result.totpSecret());
            System.out.println("\nYou will need to provide a TOTP code when logging in.");
        } else {
            System.out.println("✗ " + result.message());
        }
    }

    private void handleLogin() {
        System.out.println("\n=== Login ===");
        System.out.print("Username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Password: ");
        String password = scanner.nextLine().trim();

        System.out.print("TOTP Code: ");
        String totpCode = scanner.nextLine().trim();

        AuthService.LoginResult result = authService.login(username, password, totpCode);

        if (result.success()) {
            currentSession = result.session();
            System.out.println("\n✓ " + result.message());
            System.out.println("Welcome, " + currentSession.getUsername() + " (" + currentSession.getRole() + ")");
        } else {
            System.out.println("✗ " + result.message());
        }
    }

    private void handleLogout() {
        if (currentSession != null) {
            authService.logout(currentSession.getSessionId());
            currentSession = null;
            System.out.println("Logged out successfully.");
        }
    }

    private void handleAddEntry() {
        System.out.println("\n=== Add Vault Entry ===");
        System.out.print("Title: ");
        String title = scanner.nextLine().trim();

        System.out.print("Username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Password: ");
        String password = scanner.nextLine().trim();

        System.out.print("Notes (optional): ");
        String notes = scanner.nextLine().trim();

        VaultData data = new VaultData(title, username, password, notes);
        VaultService.VaultOperationResult result = vaultService.createEntry(currentSession, data);

        if (result.success()) {
            System.out.println("✓ " + result.message() + " (ID: " + result.entryId() + ")");
        } else {
            System.out.println("✗ " + result.message());
        }
    }

    private void handleListEntries() {
        System.out.println("\n=== Vault Entries ===");
        List<DecryptedVaultEntry> entries = vaultService.listEntries(currentSession);

        if (entries.isEmpty()) {
            System.out.println("No entries found.");
            return;
        }

        for (DecryptedVaultEntry entry : entries) {
            System.out.printf("[%s] %s - %s%n",
                    entry.getId().toString().substring(0, 8),
                    entry.getData().getTitle(),
                    entry.getData().getUsername());
        }
    }

    private void handleViewEntry() {
        System.out.print("Entry ID: ");
        String idStr = scanner.nextLine().trim();

        try {
            UUID entryId = UUID.fromString(idStr);
            var entryOpt = vaultService.getEntry(currentSession, entryId);

            if (entryOpt.isPresent()) {
                DecryptedVaultEntry entry = entryOpt.get();
                System.out.println("\n=== Vault Entry ===");
                System.out.println("Title: " + entry.getData().getTitle());
                System.out.println("Username: " + entry.getData().getUsername());
                System.out.println("Password: " + entry.getData().getPassword());
                System.out.println("Notes: " + entry.getData().getNotes());
                System.out.println("Created: " + entry.getCreatedAt());
                System.out.println("Updated: " + entry.getUpdatedAt());
            } else {
                System.out.println("Entry not found or access denied.");
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid entry ID format.");
        }
    }

    private void handleEditEntry() {
        System.out.print("Entry ID: ");
        String idStr = scanner.nextLine().trim();

        try {
            UUID entryId = UUID.fromString(idStr);
            var entryOpt = vaultService.getEntry(currentSession, entryId);

            if (entryOpt.isEmpty()) {
                System.out.println("Entry not found or access denied.");
                return;
            }

            DecryptedVaultEntry entry = entryOpt.get();
            System.out.println("\n=== Edit Vault Entry ===");
            System.out.println("Leave blank to keep current value.");

            System.out.print("Title [" + entry.getData().getTitle() + "]: ");
            String title = scanner.nextLine().trim();
            if (title.isEmpty())
                title = entry.getData().getTitle();

            System.out.print("Username [" + entry.getData().getUsername() + "]: ");
            String username = scanner.nextLine().trim();
            if (username.isEmpty())
                username = entry.getData().getUsername();

            System.out.print("Password [" + entry.getData().getPassword() + "]: ");
            String password = scanner.nextLine().trim();
            if (password.isEmpty())
                password = entry.getData().getPassword();

            System.out.print("Notes [" + entry.getData().getNotes() + "]: ");
            String notes = scanner.nextLine().trim();
            if (notes.isEmpty())
                notes = entry.getData().getNotes();

            VaultData newData = new VaultData(title, username, password, notes);
            VaultService.VaultOperationResult result = vaultService.updateEntry(currentSession, entryId, newData);

            if (result.success()) {
                System.out.println("✓ " + result.message());
            } else {
                System.out.println("✗ " + result.message());
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid entry ID format.");
        }
    }

    private void handleDeleteEntry() {
        System.out.print("Entry ID: ");
        String idStr = scanner.nextLine().trim();

        try {
            UUID entryId = UUID.fromString(idStr);

            System.out.print("Are you sure? (yes/no): ");
            String confirm = scanner.nextLine().trim().toLowerCase();

            if (!confirm.equals("yes")) {
                System.out.println("Deletion cancelled.");
                return;
            }

            VaultService.VaultOperationResult result = vaultService.deleteEntry(currentSession, entryId);

            if (result.success()) {
                System.out.println("✓ " + result.message());
            } else {
                System.out.println("✗ " + result.message());
            }
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid entry ID format.");
        }
    }

    private void printBanner() {
        System.out.println("╔════════════════════════════════════════╗");
        System.out.println("║   Secure Password Vault with MFA      ║");
        System.out.println("║   AES-256-GCM | Argon2 | TOTP          ║");
        System.out.println("╚════════════════════════════════════════╝");
    }

    private void printUnauthenticatedMenu() {
        System.out.println("\nCommands: register | login | exit");
        System.out.print("> ");
    }

    private void printAuthenticatedMenu() {
        System.out.println("\nCommands: add | list | view | edit | delete | logout | exit");
        System.out.print("> ");
    }
}
