package com.lab.ldap.model;

/**
 * Résultat d'une tentative d'authentification utilisateur.
 * Contient le statut, les informations de l'utilisateur, les politiques de mot de passe,
 * et le nombre de tentatives incorrectes préalables.
 */
public class AuthenticationResult {

    private final boolean success;
    private final AuthStatus status;
    private final LdapUser user;
    private final int failedAttemptsBeforeSuccess;
    private final boolean passwordChangeRequired;
    private final boolean passwordExpired;
    private final long daysUntilPasswordExpiration;
    private final String errorMessage;

    private AuthenticationResult(boolean success,
                                 AuthStatus status,
                                 LdapUser user,
                                 int failedAttemptsBeforeSuccess,
                                 boolean passwordChangeRequired,
                                 boolean passwordExpired,
                                 long daysUntilPasswordExpiration,
                                 String errorMessage) {
        this.success = success;
        this.status = status;
        this.user = user;
        this.failedAttemptsBeforeSuccess = failedAttemptsBeforeSuccess;
        this.passwordChangeRequired = passwordChangeRequired;
        this.passwordExpired = passwordExpired;
        this.daysUntilPasswordExpiration = daysUntilPasswordExpiration;
        this.errorMessage = errorMessage;
    }

    public static AuthenticationResult success(LdapUser user,
                                               int failedAttemptsBeforeSuccess,
                                               boolean passwordChangeRequired,
                                               boolean passwordExpired,
                                               long daysUntilPasswordExpiration) {
        return new AuthenticationResult(
                true,
                AuthStatus.SUCCESS,
                user,
                failedAttemptsBeforeSuccess,
                passwordChangeRequired,
                passwordExpired,
                daysUntilPasswordExpiration,
                null
        );
    }

    public static AuthenticationResult failure(AuthStatus status, String errorMessage) {
        return new AuthenticationResult(
                false,
                status,
                null,
                0,
                false,
                false,
                -1,
                errorMessage
        );
    }

    public static AuthenticationResult failure(AuthStatus status, String errorMessage, LdapUser user) {
        return new AuthenticationResult(
                false,
                status,
                user,
                user != null ? user.getFailedLoginAttempts() : 0,
                user != null && user.isMustChangePassword(),
                user != null && user.isPasswordExpired(),
                user != null && user.getDaysUntilPasswordExpiration() != null ? user.getDaysUntilPasswordExpiration() : -1,
                errorMessage
        );
    }

    public boolean isSuccess() { return success; }
    public AuthStatus getStatus() { return status; }
    public LdapUser getUser() { return user; }
    public int getFailedAttemptsBeforeSuccess() { return failedAttemptsBeforeSuccess; }
    public boolean isPasswordChangeRequired() { return passwordChangeRequired; }
    public boolean isPasswordExpired() { return passwordExpired; }
    public long getDaysUntilPasswordExpiration() { return daysUntilPasswordExpiration; }
    public String getErrorMessage() { return errorMessage; }

    @Override
    public String toString() {
        return "AuthenticationResult{" +
                "success=" + success +
                ", status=" + status +
                ", user=" + (user != null ? user.getUid() : "null") +
                ", failedAttemptsBeforeSuccess=" + failedAttemptsBeforeSuccess +
                ", passwordChangeRequired=" + passwordChangeRequired +
                ", passwordExpired=" + passwordExpired +
                ", daysUntilExpiration=" + daysUntilPasswordExpiration +
                ", error='" + errorMessage + '\'' +
                '}';
    }
}
