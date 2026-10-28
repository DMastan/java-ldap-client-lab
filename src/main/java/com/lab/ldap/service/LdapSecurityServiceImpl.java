package com.lab.ldap.service;

import com.lab.ldap.config.GroupType;
import com.lab.ldap.config.LdapConfig;
import com.lab.ldap.model.*;
import com.lab.ldap.util.LdapUtils;
import com.lab.ldap.util.PasswordHasher;

import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.time.LocalDate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Implémentation du service de sécurité LDAP / PAM.
 * Utilise les APIs standard JNDI (javax.naming.ldap) sans aucune dépendance tierce requise.
 */
public class LdapSecurityServiceImpl implements LdapSecurityService {

    private static final Logger LOGGER = Logger.getLogger(LdapSecurityServiceImpl.class.getName());

    private final LdapConfig config;

    // Suivi résilient des tentatives échouées en mémoire (par username)
    // Synchronisé également avec les attributs LDAP si ppolicy ou badPasswordCount sont configurés
    private final Map<String, Integer> failedAttemptsTracker = new ConcurrentHashMap<>();

    public LdapSecurityServiceImpl(LdapConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("La configuration LDAP ne peut pas être nulle");
        }
        this.config = config;
    }

    // =========================================================================
    // 1. AUTHENTIFICATION & CONTRÔLE D'ACCÈS
    // =========================================================================

    @Override
    public AuthenticationResult authenticate(String username, String password) {
        return authenticate(username, password, (String) null);
    }

    @Override
    public AuthenticationResult authenticate(String username, String password, String requiredGroup) {
        Set<String> groups = requiredGroup != null ? Collections.singleton(requiredGroup) : null;
        return authenticate(username, password, groups, true);
    }

    @Override
    public AuthenticationResult authenticate(String username, String password, Set<String> requiredGroups, boolean matchAll) {
        if (username == null || username.trim().isEmpty() || password == null) {
            return AuthenticationResult.failure(AuthStatus.INVALID_CREDENTIALS, "Identifiant ou mot de passe non renseigné.");
        }

        username = username.trim();

        // 1. Recherche du compte utilisateur avec le contexte administrateur
        LdapUser user;
        try {
            user = getUser(username);
            if (user == null) {
                return AuthenticationResult.failure(AuthStatus.USER_NOT_FOUND, "Utilisateur introuvable dans l'annuaire.");
            }
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Erreur de communication lors de la recherche du compte: " + username, e);
            return AuthenticationResult.failure(AuthStatus.COMMUNICATION_ERROR, "Erreur de communication avec l'annuaire LDAP: " + e.getMessage());
        }

        // Vérifier si le compte est verrouillé
        if (user.isAccountLocked()) {
            return AuthenticationResult.failure(AuthStatus.ACCOUNT_LOCKED, "Le compte est actuellement verrouillé.", user);
        }

        // 2. Récupérer le nombre d'échecs avant cette tentative
        int previousFailedAttempts = getRecordedFailedAttempts(username, user);

        // 3. Tenter le BIND LDAP avec les identifiants de l'utilisateur
        LdapContext userContext = null;
        try {
            Hashtable<String, Object> env = createUserEnvironment(user.getDn(), password);
            userContext = new InitialLdapContext(env, null);

            // BIND réussi ! Réinitialiser le compteur d'échecs
            resetFailedAttempts(username, user);

        } catch (AuthenticationException e) {
            // Échec d'authentification (mot de passe incorrect)
            int newFailedCount = recordFailedAttempt(username, user);
            user.setFailedLoginAttempts(newFailedCount);
            LOGGER.warning("Tentative d'authentification invalide pour '" + username + "' (échecs consécutifs: " + newFailedCount + ")");
            return AuthenticationResult.failure(AuthStatus.INVALID_CREDENTIALS, "Identifiants invalides (tentative " + newFailedCount + ").", user);

        } catch (NamingException e) {
            LOGGER.log(Level.SEVERE, "Erreur de connexion LDAP pour l'utilisateur: " + username, e);
            return AuthenticationResult.failure(AuthStatus.COMMUNICATION_ERROR, "Impossible de joindre le serveur LDAP: " + e.getMessage());
        } finally {
            closeQuietly(userContext);
        }

        // 4. Contrôle d'appartenance aux groupes exigés (si demandé)
        if (requiredGroups != null && !requiredGroups.isEmpty()) {
            Set<String> userGroups = user.getGroups();
            boolean authorized;
            if (matchAll) {
                authorized = userGroups.containsAll(requiredGroups);
            } else {
                authorized = requiredGroups.stream().anyMatch(userGroups::contains);
            }

            if (!authorized) {
                LOGGER.warning("Utilisateur '" + username + "' authentifié avec succès mais groupe requis absent. Groupes user: "
                        + userGroups + ", Requis: " + requiredGroups);
                return AuthenticationResult.failure(
                        AuthStatus.GROUP_NOT_AUTHORIZED,
                        "Accès refusé : l'utilisateur n'appartient pas au(x) groupe(s) requis " + requiredGroups,
                        user
                );
            }
        }

        // 5. Évaluation de l'état du mot de passe (expiration et renouvellement forcé)
        boolean mustChange = user.isMustChangePassword();
        boolean expired = user.isPasswordExpired();
        long daysRemaining = user.getDaysUntilPasswordExpiration() != null ? user.getDaysUntilPasswordExpiration() : -1;

        return AuthenticationResult.success(user, previousFailedAttempts, mustChange, expired, daysRemaining);
    }

    // =========================================================================
    // 2. GESTION DES MOTS DE PASSE & EXPIRATION
    // =========================================================================

    @Override
    public void changePassword(String username, String oldPassword, String newPassword) {
        if (newPassword == null || newPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Le nouveau mot de passe ne peut pas être vide");
        }

        // Valider l'ancien mot de passe via authentification directe
        LdapUser user = getUser(username);
        if (user == null) {
            throw new IllegalArgumentException("Utilisateur introuvable: " + username);
        }

        LdapContext userCtx = null;
        try {
            Hashtable<String, Object> env = createUserEnvironment(user.getDn(), oldPassword);
            userCtx = new InitialLdapContext(env, null);
        } catch (NamingException e) {
            throw new SecurityException("L'ancien mot de passe fourni est incorrect pour l'utilisateur: " + username, e);
        } finally {
            closeQuietly(userCtx);
        }

        // Appliquer le nouveau mot de passe haché en SSHA et réinitialiser shadowLastChange au jour courant
        long todayEpochDays = LdapUtils.getCurrentEpochDays();
        String hashedNewPassword = PasswordHasher.hashSSHA(newPassword);

        List<ModificationItem> mods = new ArrayList<>();
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", hashedNewPassword)));
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("shadowLastChange", String.valueOf(todayEpochDays))));

        // Si l'attribut ppolicy pwdReset était présent, le supprimer ou passer à FALSE
        if (user.getCustomAttributes().containsKey("pwdReset")) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("pwdReset", "FALSE")));
        }

        executeAdminModify(user.getDn(), mods.toArray(new ModificationItem[0]));
        LOGGER.info("Mot de passe modifié avec succès pour l'utilisateur: " + username);
    }

    @Override
    public void adminResetPassword(String username, String newPassword, boolean forceChangeAtNextLogin) {
        LdapUser user = getUser(username);
        if (user == null) {
            throw new IllegalArgumentException("Utilisateur introuvable: " + username);
        }

        String hashedPassword = PasswordHasher.hashSSHA(newPassword);
        long lastChangeValue = forceChangeAtNextLogin ? 0 : LdapUtils.getCurrentEpochDays();

        List<ModificationItem> mods = new ArrayList<>();
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("userPassword", hashedPassword)));
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("shadowLastChange", String.valueOf(lastChangeValue))));

        executeAdminModify(user.getDn(), mods.toArray(new ModificationItem[0]));

        if (forceChangeAtNextLogin) {
            try {
                executeAdminModify(user.getDn(), new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("pwdReset", "TRUE")));
            } catch (Exception ignored) {}
        }

        LOGGER.info("Réinitialisation admin du mot de passe pour '" + username + "' (forceChangeAtNextLogin=" + forceChangeAtNextLogin + ")");
    }

    @Override
    public boolean isPasswordChangeRequired(String username) {
        LdapUser user = getUser(username);
        if (user == null) return false;
        return user.isMustChangePassword() || user.isPasswordExpired();
    }

    @Override
    public void requestPasswordReset(String username) {
        // Positionne shadowLastChange à 0 (standard POSIX shadowAccount pour Linux/PAM)
        LdapUser user = getUser(username);
        if (user == null) {
            throw new IllegalArgumentException("Utilisateur introuvable: " + username);
        }

        List<ModificationItem> mods = new ArrayList<>();
        mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("shadowLastChange", "0")));
        executeAdminModify(user.getDn(), mods.toArray(new ModificationItem[0]));

        // Si l'overlay ppolicy est chargé sur le serveur LDAP, positionner également pwdReset=TRUE
        try {
            executeAdminModify(user.getDn(), new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("pwdReset", "TRUE")));
        } catch (Exception ignored) {}

        LOGGER.info("Demande de réinitialisation de mot de passe programmée pour '" + username + "' (shadowLastChange=0)");
    }

    // =========================================================================
    // 3. GESTION DES UTILISATEURS (CRUD)
    // =========================================================================

    @Override
    public LdapUser getUser(String username) {
        if (username == null || username.trim().isEmpty()) return null;
        username = username.trim();

        LdapContext ctx = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            ctx = createAdminContext();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{
                    "*", "+", "shadowLastChange", "shadowMax", "shadowWarning", "shadowExpire",
                    "pwdReset", "pwdFailureTime", "pwdAccountLockedTime", "badPasswordCount"
            });

            String filter = "(&(objectClass=*)(" + config.getUserIdAttribute() + "=" + LdapUtils.escapeLdapFilter(username) + "))";
            results = ctx.search(config.getUsersFullDn(), filter, controls);

            if (results.hasMore()) {
                SearchResult sr = results.next();
                LdapUser user = mapSearchResultToUser(sr);
                // Charger également les groupes de l'utilisateur
                user.setGroups(getUserGroups(username));
                return user;
            }
            return null;
        } catch (NamingException e) {
            LOGGER.log(Level.SEVERE, "Erreur lors de la récupération de l'utilisateur: " + username, e);
            throw new RuntimeException("Erreur LDAP lors de la recherche du compte " + username, e);
        } finally {
            closeQuietly(results);
            closeQuietly(ctx);
        }
    }

    @Override
    public boolean userExists(String username) {
        return getUser(username) != null;
    }

    @Override
    public void createUser(LdapUser user, String initialPassword, Integer passwordMaxDays, boolean forceChangeAtNextLogin) {
        if (user == null || user.getUid() == null || user.getUid().trim().isEmpty()) {
            throw new IllegalArgumentException("L'identifiant uid de l'utilisateur est obligatoire");
        }
        if (initialPassword == null || initialPassword.trim().isEmpty()) {
            throw new IllegalArgumentException("Le mot de passe initial est obligatoire");
        }

        String username = user.getUid().trim();
        if (userExists(username)) {
            throw new IllegalStateException("L'utilisateur '" + username + "' existe déjà dans l'annuaire");
        }

        // Attribution automatique d'un uidNumber si non précisé
        if (user.getUidNumber() == null) {
            user.setUidNumber(getNextAvailableUidNumber());
        }
        if (user.getGidNumber() == null) {
            user.setGidNumber((long) config.getDefaultGidNumber());
        }
        if (user.getHomeDirectory() == null) {
            user.setHomeDirectory(config.getDefaultHomePrefix() + username);
        }
        if (user.getLoginShell() == null) {
            user.setLoginShell(config.getDefaultShell());
        }
        if (user.getCommonName() == null) {
            user.setCommonName(username);
        }
        if (user.getSurname() == null) {
            user.setSurname(username);
        }

        String userDn = config.getUserIdAttribute() + "=" + LdapUtils.escapeDnComponent(username) + "," + config.getUsersFullDn();
        user.setDn(userDn);

        Attributes attrs = new BasicAttributes(true);

        // 1. Classes d'objets (POSIX + inetOrgPerson + shadowAccount pour PAM)
        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("person");
        oc.add("organizationalPerson");
        oc.add("inetOrgPerson");
        oc.add("posixAccount");
        oc.add("shadowAccount");
        attrs.put(oc);

        // 2. Attributs d'identification
        attrs.put(new BasicAttribute(config.getUserIdAttribute(), username));
        attrs.put(new BasicAttribute("cn", user.getCommonName()));
        attrs.put(new BasicAttribute("sn", user.getSurname()));
        if (user.getGivenName() != null) attrs.put(new BasicAttribute("givenName", user.getGivenName()));
        if (user.getMail() != null) attrs.put(new BasicAttribute("mail", user.getMail()));

        // 3. Attributs système POSIX (reconnus par NSS / PAM / getent passwd)
        attrs.put(new BasicAttribute("uidNumber", String.valueOf(user.getUidNumber())));
        attrs.put(new BasicAttribute("gidNumber", String.valueOf(user.getGidNumber())));
        attrs.put(new BasicAttribute("homeDirectory", user.getHomeDirectory()));
        attrs.put(new BasicAttribute("loginShell", user.getLoginShell()));
        attrs.put(new BasicAttribute("gecos", user.getGecos() != null ? user.getGecos() : username + " User"));

        // 4. Mot de passe haché SSHA
        attrs.put(new BasicAttribute("userPassword", PasswordHasher.hashSSHA(initialPassword)));

        // 5. Politiques shadowAccount pour expiration du mot de passe
        long lastChange = forceChangeAtNextLogin ? 0 : LdapUtils.getCurrentEpochDays();
        int maxDays = (passwordMaxDays != null && passwordMaxDays > 0) ? passwordMaxDays : 99999;
        attrs.put(new BasicAttribute("shadowLastChange", String.valueOf(lastChange)));
        attrs.put(new BasicAttribute("shadowMax", String.valueOf(maxDays)));
        attrs.put(new BasicAttribute("shadowWarning", "7"));


        // 6. Injection des attributs additionnels
        if (user.getCustomAttributes() != null) {
            for (Map.Entry<String, List<String>> entry : user.getCustomAttributes().entrySet()) {
                if (attrs.get(entry.getKey()) == null && !entry.getValue().isEmpty()) {
                    Attribute attr = new BasicAttribute(entry.getKey());
                    for (String val : entry.getValue()) attr.add(val);
                    attrs.put(attr);
                }
            }
        }

        LdapContext ctx = null;
        try {
            ctx = createAdminContext();
            ctx.createSubcontext(userDn, attrs);
            LOGGER.info("Utilisateur créé avec succès dans LDAP: " + userDn);
        } catch (NamingException e) {
            LOGGER.log(Level.SEVERE, "Échec de création du compte: " + userDn, e);
            throw new RuntimeException("Échec de création LDAP pour l'utilisateur " + username + ": " + e.getMessage(), e);
        } finally {
            closeQuietly(ctx);
        }

        // 7. Rattachement aux groupes demandés
        if (user.getGroups() != null) {
            for (String groupName : user.getGroups()) {
                try {
                    addUserToGroup(username, groupName);
                } catch (Exception e) {
                    LOGGER.warning("Impossible d'ajouter l'utilisateur au groupe '" + groupName + "': " + e.getMessage());
                }
            }
        }
    }

    @Override
    public void deleteUser(String username, boolean removeFromGroups) {
        LdapUser user = getUser(username);
        if (user == null) {
            LOGGER.warning("Tentative de suppression d'un utilisateur inexistant: " + username);
            return;
        }

        // Retirer des groupes si demandé
        if (removeFromGroups && user.getGroups() != null) {
            for (String grp : user.getGroups()) {
                try {
                    removeUserFromGroup(username, grp);
                } catch (Exception e) {
                    LOGGER.warning("Erreur lors du retrait de l'utilisateur du groupe '" + grp + "': " + e.getMessage());
                }
            }
        }

        LdapContext ctx = null;
        try {
            ctx = createAdminContext();
            ctx.destroySubcontext(user.getDn());
            failedAttemptsTracker.remove(username);
            LOGGER.info("Utilisateur supprimé de l'annuaire LDAP: " + user.getDn());
        } catch (NamingException e) {
            LOGGER.log(Level.SEVERE, "Erreur lors de la suppression de: " + user.getDn(), e);
            throw new RuntimeException("Échec de suppression du compte: " + e.getMessage(), e);
        } finally {
            closeQuietly(ctx);
        }
    }

    @Override
    public void updateUser(LdapUser user) {
        if (user == null || user.getUid() == null) {
            throw new IllegalArgumentException("Utilisateur invalide pour mise à jour");
        }

        LdapUser existing = getUser(user.getUid());
        if (existing == null) {
            throw new IllegalArgumentException("Utilisateur introuvable pour mise à jour: " + user.getUid());
        }

        List<ModificationItem> mods = new ArrayList<>();

        if (user.getCommonName() != null && !user.getCommonName().equals(existing.getCommonName())) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("cn", user.getCommonName())));
        }
        if (user.getSurname() != null && !user.getSurname().equals(existing.getSurname())) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("sn", user.getSurname())));
        }
        if (user.getGivenName() != null && !user.getGivenName().equals(existing.getGivenName())) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("givenName", user.getGivenName())));
        }
        if (user.getMail() != null && !user.getMail().equals(existing.getMail())) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("mail", user.getMail())));
        }
        if (user.getHomeDirectory() != null && !user.getHomeDirectory().equals(existing.getHomeDirectory())) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("homeDirectory", user.getHomeDirectory())));
        }
        if (user.getLoginShell() != null && !user.getLoginShell().equals(existing.getLoginShell())) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("loginShell", user.getLoginShell())));
        }
        if (user.getGecos() != null && !user.getGecos().equals(existing.getGecos())) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("gecos", user.getGecos())));
        }
        if (user.getShadowMax() != null && !user.getShadowMax().equals(existing.getShadowMax())) {
            mods.add(new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("shadowMax", String.valueOf(user.getShadowMax()))));
        }

        if (!mods.isEmpty()) {
            executeAdminModify(existing.getDn(), mods.toArray(new ModificationItem[0]));
            LOGGER.info("Profil utilisateur mis à jour pour: " + user.getUid());
        }

        // Synchroniser les groupes si fournis
        if (user.getGroups() != null) {
            Set<String> currentGroups = existing.getGroups();
            Set<String> desiredGroups = user.getGroups();

            // Groupes à ajouter
            for (String g : desiredGroups) {
                if (!currentGroups.contains(g)) {
                    addUserToGroup(user.getUid(), g);
                }
            }
            // Groupes à retirer
            for (String g : currentGroups) {
                if (!desiredGroups.contains(g)) {
                    removeUserFromGroup(user.getUid(), g);
                }
            }
        }
    }

    // =========================================================================
    // 4. GESTION DES GROUPES
    // =========================================================================

    @Override
    public void addUserToGroup(String username, String groupName) {
        LdapGroup group = getGroup(groupName);
        if (group == null) {
            throw new IllegalArgumentException("Le groupe '" + groupName + "' n'existe pas dans l'annuaire");
        }

        LdapUser user = getUser(username);
        if (user == null) {
            throw new IllegalArgumentException("L'utilisateur '" + username + "' n'existe pas dans l'annuaire");
        }

        String memberAttr;
        String memberValue;

        if (group.getGroupType() == GroupType.POSIX_GROUP) {
            memberAttr = config.getPosixMemberAttribute(); // "memberUid"
            memberValue = username;
        } else {
            memberAttr = config.getDnMemberAttribute();    // "member"
            memberValue = user.getDn();
        }

        ModificationItem mod = new ModificationItem(DirContext.ADD_ATTRIBUTE, new BasicAttribute(memberAttr, memberValue));
        try {
            executeAdminModify(group.getDn(), mod);
            LOGGER.info("Utilisateur '" + username + "' rattaché au groupe '" + groupName + "' (" + memberAttr + "=" + memberValue + ")");
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("Attribute Or Value Exists")) {
                LOGGER.fine("L'utilisateur est déjà membre du groupe: " + groupName);
            } else {
                throw new RuntimeException("Échec de l'ajout au groupe " + groupName + ": " + e.getMessage(), e);
            }
        }
    }

    @Override
    public void removeUserFromGroup(String username, String groupName) {
        LdapGroup group = getGroup(groupName);
        if (group == null) return;

        LdapUser user = getUser(username);
        String memberAttr = group.getGroupType() == GroupType.POSIX_GROUP
                ? config.getPosixMemberAttribute()
                : config.getDnMemberAttribute();

        String memberValue = group.getGroupType() == GroupType.POSIX_GROUP
                ? username
                : (user != null ? user.getDn() : config.getUserIdAttribute() + "=" + username + "," + config.getUsersFullDn());

        ModificationItem mod = new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute(memberAttr, memberValue));
        try {
            executeAdminModify(group.getDn(), mod);
            LOGGER.info("Utilisateur '" + username + "' retiré du groupe '" + groupName + "'");
        } catch (Exception e) {
            // Ignorer si l'attribut n'existait pas déjà
            LOGGER.warning("Avertissement lors du retrait du groupe " + groupName + ": " + e.getMessage());
        }
    }

    @Override
    public Set<String> getUserGroups(String username) {
        Set<String> groups = new HashSet<>();
        if (username == null || username.trim().isEmpty()) return groups;

        LdapContext ctx = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            ctx = createAdminContext();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{config.getGroupNameAttribute(), "objectClass", "gidNumber"});

            String escapedUid = LdapUtils.escapeLdapFilter(username);
            String userDn = config.getUserIdAttribute() + "=" + LdapUtils.escapeDnComponent(username) + "," + config.getUsersFullDn();
            String escapedDn = LdapUtils.escapeLdapFilter(userDn);

            // Recherche combinée : posixGroup (memberUid) OU groupOfNames (member)
            String filter = "(|(" + config.getPosixMemberAttribute() + "=" + escapedUid + ")"
                    + "(" + config.getDnMemberAttribute() + "=" + escapedDn + "))";

            results = ctx.search(config.getGroupsFullDn(), filter, controls);
            while (results.hasMore()) {
                SearchResult sr = results.next();
                Attribute cnAttr = sr.getAttributes().get(config.getGroupNameAttribute());
                if (cnAttr != null) {
                    groups.add((String) cnAttr.get());
                }
            }
        } catch (NamingException e) {
            LOGGER.log(Level.SEVERE, "Erreur lors de la recherche des groupes pour: " + username, e);
        } finally {
            closeQuietly(results);
            closeQuietly(ctx);
        }
        return groups;
    }

    public LdapGroup getGroup(String groupName) {
        if (groupName == null || groupName.trim().isEmpty()) return null;

        LdapContext ctx = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            ctx = createAdminContext();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            String filter = "(&(objectClass=*)(" + config.getGroupNameAttribute() + "=" + LdapUtils.escapeLdapFilter(groupName) + "))";
            results = ctx.search(config.getGroupsFullDn(), filter, controls);

            if (results.hasMore()) {
                SearchResult sr = results.next();
                Attributes attrs = sr.getAttributes();
                LdapGroup g = new LdapGroup(groupName);
                g.setDn(sr.getNameInNamespace());

                Attribute oc = attrs.get("objectClass");
                if (oc != null) {
                    boolean isPosix = false;
                    for (int i = 0; i < oc.size(); i++) {
                        if ("posixGroup".equalsIgnoreCase((String) oc.get(i))) {
                            isPosix = true;
                            break;
                        }
                    }
                    g.setGroupType(isPosix ? GroupType.POSIX_GROUP : GroupType.GROUP_OF_NAMES);
                }

                Attribute gid = attrs.get("gidNumber");
                if (gid != null) g.setGidNumber(Long.parseLong((String) gid.get()));

                Attribute desc = attrs.get("description");
                if (desc != null) g.setDescription((String) desc.get());

                return g;
            }
            return null;
        } catch (NamingException e) {
            throw new RuntimeException("Erreur de recherche du groupe " + groupName, e);
        } finally {
            closeQuietly(results);
            closeQuietly(ctx);
        }
    }

    @Override
    public void createGroup(String groupName, Long gidNumber, String description) {
        if (groupName == null || groupName.trim().isEmpty()) {
            throw new IllegalArgumentException("Nom de groupe obligatoire");
        }

        String groupDn = config.getGroupNameAttribute() + "=" + LdapUtils.escapeDnComponent(groupName) + "," + config.getGroupsFullDn();
        Attributes attrs = new BasicAttributes(true);

        Attribute oc = new BasicAttribute("objectClass");
        oc.add("top");
        oc.add("posixGroup");
        attrs.put(oc);

        attrs.put(new BasicAttribute(config.getGroupNameAttribute(), groupName));
        attrs.put(new BasicAttribute("gidNumber", String.valueOf(gidNumber != null ? gidNumber : getNextAvailableGidNumber())));
        if (description != null) attrs.put(new BasicAttribute("description", description));

        LdapContext ctx = null;
        try {
            ctx = createAdminContext();
            ctx.createSubcontext(groupDn, attrs);
            LOGGER.info("Groupe POSIX créé dans LDAP: " + groupDn);
        } catch (NamingException e) {
            throw new RuntimeException("Impossible de créer le groupe " + groupName + ": " + e.getMessage(), e);
        } finally {
            closeQuietly(ctx);
        }
    }

    @Override
    public void unlockAccount(String username) {
        LdapUser user = getUser(username);
        if (user == null) return;

        failedAttemptsTracker.remove(username);

        List<ModificationItem> mods = new ArrayList<>();
        // Retirer pwdAccountLockedTime si présent
        mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("pwdAccountLockedTime")));
        // Retirer pwdFailureTime si présent
        mods.add(new ModificationItem(DirContext.REMOVE_ATTRIBUTE, new BasicAttribute("pwdFailureTime")));

        try {
            executeAdminModify(user.getDn(), mods.toArray(new ModificationItem[0]));
        } catch (Exception ignored) {
            // Si les attributs ppolicy n'étaient pas initialisés, ignorer l'erreur
        }
        LOGGER.info("Compte déverrouillé et compteur d'échecs réinitialisé pour: " + username);
    }

    @Override
    public List<LdapUser> listUsers() {
        List<LdapUser> list = new ArrayList<>();
        LdapContext ctx = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            ctx = createAdminContext();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{
                    "*", "+", "shadowLastChange", "shadowMax", "shadowWarning"
            });
            String filter = "(objectClass=posixAccount)";
            results = ctx.search(config.getUsersFullDn(), filter, controls);
            while (results.hasMore()) {
                list.add(mapSearchResultToUser(results.next()));
            }
        } catch (NamingException e) {
            LOGGER.log(Level.SEVERE, "Erreur lors du listage des utilisateurs", e);
        } finally {
            closeQuietly(results);
            closeQuietly(ctx);
        }
        return list;
    }

    // =========================================================================
    // 5. GESTION DES TENTATIVES ÉCHOUÉES & COMPTEURS
    // =========================================================================

    private int getRecordedFailedAttempts(String username, LdapUser user) {
        // 1. Vérifier si ppolicy expose pwdFailureTime
        List<String> pwdFailureTimes = user.getCustomAttributes().get("pwdFailureTime");
        if (pwdFailureTimes != null && !pwdFailureTimes.isEmpty()) {
            return pwdFailureTimes.size();
        }

        // 2. Vérifier si un attribut badPasswordCount existe
        List<String> badCounts = user.getCustomAttributes().get("badPasswordCount");
        if (badCounts != null && !badCounts.isEmpty()) {
            try {
                return Integer.parseInt(badCounts.get(0));
            } catch (NumberFormatException ignored) {}
        }

        // 3. Fallback sur le tracker mémoire du service
        return failedAttemptsTracker.getOrDefault(username, 0);
    }

    private int recordFailedAttempt(String username, LdapUser user) {
        int count = failedAttemptsTracker.compute(username, (k, v) -> (v == null) ? 1 : v + 1);

        // Si l'annuaire supporte badPasswordCount, le mettre à jour
        try {
            ModificationItem mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                    new BasicAttribute("badPasswordCount", String.valueOf(count)));
            executeAdminModify(user.getDn(), mod);
        } catch (Exception ignored) {
            // Attribut non standard non présent dans le schéma slapd, pas bloquant
        }

        return count;
    }

    private void resetFailedAttempts(String username, LdapUser user) {
        failedAttemptsTracker.remove(username);

        // Si badPasswordCount était stocké, le remettre à 0
        try {
            ModificationItem mod = new ModificationItem(DirContext.REPLACE_ATTRIBUTE,
                    new BasicAttribute("badPasswordCount", "0"));
            executeAdminModify(user.getDn(), mod);
        } catch (Exception ignored) {}
    }

    // =========================================================================
    // 6. MÉTHODES TECHNIQUES INTERNES
    // =========================================================================

    private LdapContext createAdminContext() throws NamingException {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, config.getProviderUrl());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, config.getAdminDn());
        env.put(Context.SECURITY_CREDENTIALS, config.getAdminPassword());
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(config.getConnectionTimeoutMs()));
        env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(config.getReadTimeoutMs()));
        return new InitialLdapContext(env, null);
    }

    private Hashtable<String, Object> createUserEnvironment(String userDn, String password) {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, config.getProviderUrl());
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDn);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(config.getConnectionTimeoutMs()));
        env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(config.getReadTimeoutMs()));
        return env;
    }

    private void executeAdminModify(String dn, ModificationItem... mods) {
        LdapContext ctx = null;
        try {
            ctx = createAdminContext();
            ctx.modifyAttributes(dn, mods);
        } catch (NamingException e) {
            throw new RuntimeException("Erreur de modification LDAP sur '" + dn + "': " + e.getMessage(), e);
        } finally {
            closeQuietly(ctx);
        }
    }

    private LdapUser mapSearchResultToUser(SearchResult sr) throws NamingException {
        Attributes attrs = sr.getAttributes();
        String uid = getAttributeValue(attrs, config.getUserIdAttribute());
        LdapUser user = new LdapUser(uid);
        user.setDn(sr.getNameInNamespace());

        user.setCommonName(getAttributeValue(attrs, "cn"));
        user.setSurname(getAttributeValue(attrs, "sn"));
        user.setGivenName(getAttributeValue(attrs, "givenName"));
        user.setMail(getAttributeValue(attrs, "mail"));

        String uidNum = getAttributeValue(attrs, "uidNumber");
        if (uidNum != null) user.setUidNumber(Long.parseLong(uidNum));

        String gidNum = getAttributeValue(attrs, "gidNumber");
        if (gidNum != null) user.setGidNumber(Long.parseLong(gidNum));

        user.setHomeDirectory(getAttributeValue(attrs, "homeDirectory"));
        user.setLoginShell(getAttributeValue(attrs, "loginShell"));
        user.setGecos(getAttributeValue(attrs, "gecos"));

        // shadowAccount parsing (gestion de l'expiration du mot de passe)
        String shadowLast = getAttributeValue(attrs, "shadowLastChange");
        if (shadowLast != null) {
            try {
                long lastChangeDays = Long.parseLong(shadowLast);
                user.setShadowLastChange(lastChangeDays);

                // Convention standard Linux / PAM : 0 signifie "changement de mot de passe obligatoire"
                if (lastChangeDays == 0) {
                    user.setMustChangePassword(true);
                }
            } catch (NumberFormatException ignored) {}
        }

        String shadowMax = getAttributeValue(attrs, "shadowMax");
        if (shadowMax != null) {
            try {
                int maxDays = Integer.parseInt(shadowMax);
                user.setShadowMax(maxDays);

                if (user.getShadowLastChange() != null && user.getShadowLastChange() > 0 && maxDays < 99999) {
                    long currentDays = LdapUtils.getCurrentEpochDays();
                    long daysSinceChange = currentDays - user.getShadowLastChange();
                    long remaining = maxDays - daysSinceChange;
                    user.setDaysUntilPasswordExpiration(remaining);

                    if (remaining <= 0) {
                        user.setPasswordExpired(true);
                        user.setMustChangePassword(true);
                    }
                    user.setPasswordExpiresAt(LdapUtils.epochDaysToLocalDate(user.getShadowLastChange() + maxDays));
                }
            } catch (NumberFormatException ignored) {}
        }

        // Examen de ppolicy (pwdReset / pwdAccountLockedTime / pwdFailureTime)
        String pwdReset = getAttributeValue(attrs, "pwdReset");
        if ("TRUE".equalsIgnoreCase(pwdReset)) {
            user.setMustChangePassword(true);
        }

        String lockedTime = getAttributeValue(attrs, "pwdAccountLockedTime");
        if (lockedTime != null && !lockedTime.isEmpty()) {
            user.setAccountLocked(true);
        }

        // Conserver tous les attributs dans customAttributes
        NamingEnumeration<? extends Attribute> allAttrs = attrs.getAll();
        while (allAttrs.hasMore()) {
            Attribute a = allAttrs.next();
            List<String> values = new ArrayList<>();
            for (int i = 0; i < a.size(); i++) {
                Object val = a.get(i);
                if (val instanceof String) {
                    values.add((String) val);
                } else if (val instanceof byte[]) {
                    values.add(new String((byte[]) val));
                }
            }
            user.getCustomAttributes().put(a.getID(), values);
        }

        user.setFailedLoginAttempts(getRecordedFailedAttempts(uid, user));
        return user;
    }

    private String getAttributeValue(Attributes attrs, String attrId) throws NamingException {
        Attribute attr = attrs.get(attrId);
        if (attr == null || attr.get() == null) return null;
        Object val = attr.get();
        if (val instanceof byte[]) {
            return new String((byte[]) val);
        }
        return val.toString();
    }

    private synchronized long getNextAvailableUidNumber() {
        long maxUid = config.getDefaultMinUidNumber();
        LdapContext ctx = null;
        NamingEnumeration<SearchResult> results = null;
        try {
            ctx = createAdminContext();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{"uidNumber"});
            results = ctx.search(config.getUsersFullDn(), "(uidNumber=*)", controls);
            while (results.hasMore()) {
                SearchResult sr = results.next();
                Attribute a = sr.getAttributes().get("uidNumber");
                if (a != null) {
                    try {
                        long val = Long.parseLong((String) a.get());
                        if (val > maxUid) maxUid = val;
                    } catch (NumberFormatException ignored) {}
                }
            }
            return maxUid + 1;
        } catch (Exception e) {
            return config.getDefaultMinUidNumber() + 10;
        } finally {
            closeQuietly(results);
            closeQuietly(ctx);
        }
    }

    private synchronized long getNextAvailableGidNumber() {
        return config.getDefaultGidNumber();
    }

    private void closeQuietly(Context ctx) {
        if (ctx != null) {
            try {
                ctx.close();
            } catch (Exception ignored) {}
        }
    }

    private void closeQuietly(NamingEnumeration<?> enumeration) {
        if (enumeration != null) {
            try {
                enumeration.close();
            } catch (Exception ignored) {}
        }
    }
}
