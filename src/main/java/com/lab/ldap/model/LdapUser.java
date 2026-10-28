package com.lab.ldap.model;

import java.time.LocalDate;
import java.util.*;

/**
 * Représente un compte utilisateur LDAP / PAM.
 * Regroupe les attributs d'annuaire (inetOrgPerson), les attributs système (posixAccount)
 * et les politiques d'expiration (shadowAccount / ppolicy).
 */
public class LdapUser {

    private String uid;
    private String dn;
    private String commonName;
    private String surname;
    private String givenName;
    private String mail;

    // Attributs POSIX (PAM / NSS)
    private Long uidNumber;
    private Long gidNumber;
    private String homeDirectory;
    private String loginShell;
    private String gecos;

    // Groupes dont l'utilisateur fait partie
    private Set<String> groups = new HashSet<>();

    // Sécurité & Expiration (shadowAccount / ppolicy)
    private Long shadowLastChange;
    private Integer shadowMax;
    private Integer shadowWarning;
    private boolean mustChangePassword;
    private boolean passwordExpired;
    private LocalDate passwordExpiresAt;
    private Long daysUntilPasswordExpiration;
    private boolean accountLocked;
    private int failedLoginAttempts;

    // Attributs additionnels libres pour adapter à une base personnalisée
    private Map<String, List<String>> customAttributes = new HashMap<>();

    public LdapUser() {}

    public LdapUser(String uid) {
        this.uid = uid;
    }

    public static Builder builder(String uid) {
        return new Builder(uid);
    }

    // Getters & Setters
    public String getUid() { return uid; }
    public void setUid(String uid) { this.uid = uid; }

    public String getDn() { return dn; }
    public void setDn(String dn) { this.dn = dn; }

    public String getCommonName() { return commonName; }
    public void setCommonName(String commonName) { this.commonName = commonName; }

    public String getSurname() { return surname; }
    public void setSurname(String surname) { this.surname = surname; }

    public String getGivenName() { return givenName; }
    public void setGivenName(String givenName) { this.givenName = givenName; }

    public String getMail() { return mail; }
    public void setMail(String mail) { this.mail = mail; }

    public Long getUidNumber() { return uidNumber; }
    public void setUidNumber(Long uidNumber) { this.uidNumber = uidNumber; }

    public Long getGidNumber() { return gidNumber; }
    public void setGidNumber(Long gidNumber) { this.gidNumber = gidNumber; }

    public String getHomeDirectory() { return homeDirectory; }
    public void setHomeDirectory(String homeDirectory) { this.homeDirectory = homeDirectory; }

    public String getLoginShell() { return loginShell; }
    public void setLoginShell(String loginShell) { this.loginShell = loginShell; }

    public String getGecos() { return gecos; }
    public void setGecos(String gecos) { this.gecos = gecos; }

    public Set<String> getGroups() { return groups; }
    public void setGroups(Set<String> groups) { this.groups = groups != null ? groups : new HashSet<>(); }

    public Long getShadowLastChange() { return shadowLastChange; }
    public void setShadowLastChange(Long shadowLastChange) { this.shadowLastChange = shadowLastChange; }

    public Integer getShadowMax() { return shadowMax; }
    public void setShadowMax(Integer shadowMax) { this.shadowMax = shadowMax; }

    public Integer getShadowWarning() { return shadowWarning; }
    public void setShadowWarning(Integer shadowWarning) { this.shadowWarning = shadowWarning; }

    public boolean isMustChangePassword() { return mustChangePassword; }
    public void setMustChangePassword(boolean mustChangePassword) { this.mustChangePassword = mustChangePassword; }

    public boolean isPasswordExpired() { return passwordExpired; }
    public void setPasswordExpired(boolean passwordExpired) { this.passwordExpired = passwordExpired; }

    public LocalDate getPasswordExpiresAt() { return passwordExpiresAt; }
    public void setPasswordExpiresAt(LocalDate passwordExpiresAt) { this.passwordExpiresAt = passwordExpiresAt; }

    public Long getDaysUntilPasswordExpiration() { return daysUntilPasswordExpiration; }
    public void setDaysUntilPasswordExpiration(Long daysUntilPasswordExpiration) { this.daysUntilPasswordExpiration = daysUntilPasswordExpiration; }

    public boolean isAccountLocked() { return accountLocked; }
    public void setAccountLocked(boolean accountLocked) { this.accountLocked = accountLocked; }

    public int getFailedLoginAttempts() { return failedLoginAttempts; }
    public void setFailedLoginAttempts(int failedLoginAttempts) { this.failedLoginAttempts = failedLoginAttempts; }

    public Map<String, List<String>> getCustomAttributes() { return customAttributes; }
    public void setCustomAttributes(Map<String, List<String>> customAttributes) { this.customAttributes = customAttributes; }

    @Override
    public String toString() {
        return "LdapUser{" +
                "uid='" + uid + '\'' +
                ", dn='" + dn + '\'' +
                ", commonName='" + commonName + '\'' +
                ", uidNumber=" + uidNumber +
                ", gidNumber=" + gidNumber +
                ", groups=" + groups +
                ", mustChangePassword=" + mustChangePassword +
                ", passwordExpired=" + passwordExpired +
                ", daysUntilExpiration=" + daysUntilPasswordExpiration +
                ", failedAttempts=" + failedLoginAttempts +
                '}';
    }

    public static class Builder {
        private final LdapUser user;

        public Builder(String uid) {
            user = new LdapUser(uid);
            user.setCommonName(uid);
            user.setSurname(uid);
            user.setGivenName(uid);
        }

        public Builder commonName(String cn) { user.setCommonName(cn); return this; }
        public Builder surname(String sn) { user.setSurname(sn); return this; }
        public Builder givenName(String gn) { user.setGivenName(gn); return this; }
        public Builder mail(String mail) { user.setMail(mail); return this; }
        public Builder uidNumber(long uidNumber) { user.setUidNumber(uidNumber); return this; }
        public Builder gidNumber(long gidNumber) { user.setGidNumber(gidNumber); return this; }
        public Builder homeDirectory(String home) { user.setHomeDirectory(home); return this; }
        public Builder loginShell(String shell) { user.setLoginShell(shell); return this; }
        public Builder gecos(String gecos) { user.setGecos(gecos); return this; }
        public Builder groups(Collection<String> grps) {
            if (grps != null) user.getGroups().addAll(grps);
            return this;
        }
        public Builder group(String group) {
            user.getGroups().add(group);
            return this;
        }

        public LdapUser build() {
            return user;
        }
    }
}
