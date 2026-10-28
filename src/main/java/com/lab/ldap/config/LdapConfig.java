package com.lab.ldap.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Configuration paramétrable pour le client LDAP / PAM.
 * Permet d'adapter la bibliothèque à toute arborescence personnalisée (AD, OpenLDAP standard ou custom).
 */
public class LdapConfig {

    private String host = "127.0.0.1";
    private int port = 389;
    private boolean useSsl = false;
    private boolean useStartTls = false;

    private String baseDn = "dc=lab,dc=example,dc=org";
    private String usersOu = "ou=users";
    private String groupsOu = "ou=groups";

    private String adminDn = "cn=admin,dc=lab,dc=example,dc=org";
    private String adminPassword = "AdminSecretPassword123!";

    // Attributs de mapping personnalisables
    private String userIdAttribute = "uid";              // "uid" sous Linux/OpenLDAP, "sAMAccountName" sous AD
    private String groupNameAttribute = "cn";
    private String posixMemberAttribute = "memberUid";   // Pour posixGroup (login Unix)
    private String dnMemberAttribute = "member";         // Pour groupOfNames (DN complet)
    private GroupType defaultGroupType = GroupType.AUTO_DETECT;

    // Paramètres POSIX par défaut pour la création de comptes
    private int defaultMinUidNumber = 10000;
    private int defaultGidNumber = 10001;
    private String defaultShell = "/bin/bash";
    private String defaultHomePrefix = "/home/";

    // Timeouts réseau (en millisecondes)
    private int connectionTimeoutMs = 5000;
    private int readTimeoutMs = 10000;

    public LdapConfig() {}

    public static Builder builder() {
        return new Builder();
    }

    public static LdapConfig loadFromProperties(InputStream in) throws IOException {
        Properties props = new Properties();
        props.load(in);
        return fromProperties(props);
    }

    public static LdapConfig loadFromFile(String filePath) throws IOException {
        try (FileInputStream fis = new FileInputStream(filePath)) {
            return loadFromProperties(fis);
        }
    }

    public static LdapConfig fromProperties(Properties p) {
        LdapConfig cfg = new LdapConfig();
        if (p.containsKey("ldap.host")) cfg.setHost(p.getProperty("ldap.host"));
        if (p.containsKey("ldap.port")) cfg.setPort(Integer.parseInt(p.getProperty("ldap.port")));
        if (p.containsKey("ldap.ssl")) cfg.setUseSsl(Boolean.parseBoolean(p.getProperty("ldap.ssl")));
        if (p.containsKey("ldap.starttls")) cfg.setUseStartTls(Boolean.parseBoolean(p.getProperty("ldap.starttls")));

        if (p.containsKey("ldap.baseDn")) cfg.setBaseDn(p.getProperty("ldap.baseDn"));
        if (p.containsKey("ldap.usersOu")) cfg.setUsersOu(p.getProperty("ldap.usersOu"));
        if (p.containsKey("ldap.groupsOu")) cfg.setGroupsOu(p.getProperty("ldap.groupsOu"));

        if (p.containsKey("ldap.adminDn")) cfg.setAdminDn(p.getProperty("ldap.adminDn"));
        if (p.containsKey("ldap.adminPassword")) cfg.setAdminPassword(p.getProperty("ldap.adminPassword"));

        if (p.containsKey("ldap.attribute.user")) cfg.setUserIdAttribute(p.getProperty("ldap.attribute.user"));
        if (p.containsKey("ldap.attribute.group")) cfg.setGroupNameAttribute(p.getProperty("ldap.attribute.group"));
        if (p.containsKey("ldap.attribute.posixMember")) cfg.setPosixMemberAttribute(p.getProperty("ldap.attribute.posixMember"));
        if (p.containsKey("ldap.attribute.dnMember")) cfg.setDnMemberAttribute(p.getProperty("ldap.attribute.dnMember"));

        if (p.containsKey("ldap.posix.minUid")) cfg.setDefaultMinUidNumber(Integer.parseInt(p.getProperty("ldap.posix.minUid")));
        if (p.containsKey("ldap.posix.defaultGid")) cfg.setDefaultGidNumber(Integer.parseInt(p.getProperty("ldap.posix.defaultGid")));
        if (p.containsKey("ldap.posix.defaultShell")) cfg.setDefaultShell(p.getProperty("ldap.posix.defaultShell"));
        if (p.containsKey("ldap.posix.defaultHomePrefix")) cfg.setDefaultHomePrefix(p.getProperty("ldap.posix.defaultHomePrefix"));

        if (p.containsKey("ldap.timeout.connection")) cfg.setConnectionTimeoutMs(Integer.parseInt(p.getProperty("ldap.timeout.connection")));
        if (p.containsKey("ldap.timeout.read")) cfg.setReadTimeoutMs(Integer.parseInt(p.getProperty("ldap.timeout.read")));

        return cfg;
    }

    public String getProviderUrl() {
        String scheme = useSsl ? "ldaps://" : "ldap://";
        return scheme + host + ":" + port;
    }

    public String getUsersFullDn() {
        if (usersOu == null || usersOu.trim().isEmpty()) {
            return baseDn;
        }
        if (usersOu.endsWith(baseDn)) {
            return usersOu;
        }
        return usersOu + "," + baseDn;
    }

    public String getGroupsFullDn() {
        if (groupsOu == null || groupsOu.trim().isEmpty()) {
            return baseDn;
        }
        if (groupsOu.endsWith(baseDn)) {
            return groupsOu;
        }
        return groupsOu + "," + baseDn;
    }

    // Getters & Setters
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }

    public boolean isUseSsl() { return useSsl; }
    public void setUseSsl(boolean useSsl) { this.useSsl = useSsl; }

    public boolean isUseStartTls() { return useStartTls; }
    public void setUseStartTls(boolean useStartTls) { this.useStartTls = useStartTls; }

    public String getBaseDn() { return baseDn; }
    public void setBaseDn(String baseDn) { this.baseDn = baseDn; }

    public String getUsersOu() { return usersOu; }
    public void setUsersOu(String usersOu) { this.usersOu = usersOu; }

    public String getGroupsOu() { return groupsOu; }
    public void setGroupsOu(String groupsOu) { this.groupsOu = groupsOu; }

    public String getAdminDn() { return adminDn; }
    public void setAdminDn(String adminDn) { this.adminDn = adminDn; }

    public String getAdminPassword() { return adminPassword; }
    public void setAdminPassword(String adminPassword) { this.adminPassword = adminPassword; }

    public String getUserIdAttribute() { return userIdAttribute; }
    public void setUserIdAttribute(String userIdAttribute) { this.userIdAttribute = userIdAttribute; }

    public String getGroupNameAttribute() { return groupNameAttribute; }
    public void setGroupNameAttribute(String groupNameAttribute) { this.groupNameAttribute = groupNameAttribute; }

    public String getPosixMemberAttribute() { return posixMemberAttribute; }
    public void setPosixMemberAttribute(String posixMemberAttribute) { this.posixMemberAttribute = posixMemberAttribute; }

    public String getDnMemberAttribute() { return dnMemberAttribute; }
    public void setDnMemberAttribute(String dnMemberAttribute) { this.dnMemberAttribute = dnMemberAttribute; }

    public GroupType getDefaultGroupType() { return defaultGroupType; }
    public void setDefaultGroupType(GroupType defaultGroupType) { this.defaultGroupType = defaultGroupType; }

    public int getDefaultMinUidNumber() { return defaultMinUidNumber; }
    public void setDefaultMinUidNumber(int defaultMinUidNumber) { this.defaultMinUidNumber = defaultMinUidNumber; }

    public int getDefaultGidNumber() { return defaultGidNumber; }
    public void setDefaultGidNumber(int defaultGidNumber) { this.defaultGidNumber = defaultGidNumber; }

    public String getDefaultShell() { return defaultShell; }
    public void setDefaultShell(String defaultShell) { this.defaultShell = defaultShell; }

    public String getDefaultHomePrefix() { return defaultHomePrefix; }
    public void setDefaultHomePrefix(String defaultHomePrefix) { this.defaultHomePrefix = defaultHomePrefix; }

    public int getConnectionTimeoutMs() { return connectionTimeoutMs; }
    public void setConnectionTimeoutMs(int connectionTimeoutMs) { this.connectionTimeoutMs = connectionTimeoutMs; }

    public int getReadTimeoutMs() { return readTimeoutMs; }
    public void setReadTimeoutMs(int readTimeoutMs) { this.readTimeoutMs = readTimeoutMs; }

    public static class Builder {
        private final LdapConfig config = new LdapConfig();

        public Builder host(String host) { config.setHost(host); return this; }
        public Builder port(int port) { config.setPort(port); return this; }
        public Builder useSsl(boolean ssl) { config.setUseSsl(ssl); return this; }
        public Builder baseDn(String baseDn) { config.setBaseDn(baseDn); return this; }
        public Builder usersOu(String usersOu) { config.setUsersOu(usersOu); return this; }
        public Builder groupsOu(String groupsOu) { config.setGroupsOu(groupsOu); return this; }
        public Builder adminDn(String adminDn) { config.setAdminDn(adminDn); return this; }
        public Builder adminPassword(String adminPassword) { config.setAdminPassword(adminPassword); return this; }
        public Builder userIdAttribute(String attr) { config.setUserIdAttribute(attr); return this; }
        public Builder defaultGroupType(GroupType type) { config.setDefaultGroupType(type); return this; }
        public Builder defaultMinUidNumber(int minUid) { config.setDefaultMinUidNumber(minUid); return this; }
        public Builder defaultGidNumber(int gid) { config.setDefaultGidNumber(gid); return this; }

        public LdapConfig build() {
            return config;
        }
    }
}
