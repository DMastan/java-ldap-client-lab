package com.lab.ldap.service;

import com.lab.ldap.model.AuthenticationResult;
import com.lab.ldap.model.LdapGroup;
import com.lab.ldap.model.LdapUser;

import java.util.List;
import java.util.Set;

/**
 * Interface du service d'authentification et de gestion des identités LDAP / PAM.
 */
public interface LdapSecurityService {

    /**
     * Authentifie un utilisateur par son identifiant et mot de passe.
     * En cas de succès, renvoie le nombre de tentatives incorrectes préalables
     * et l'état d'expiration du mot de passe.
     *
     * @param username Identifiant de connexion (ex: toto)
     * @param password Mot de passe en clair
     * @return Résultat complet de l'authentification
     */
    AuthenticationResult authenticate(String username, String password);

    /**
     * Authentifie un utilisateur en exigeant l'appartenance à un groupe spécifique.
     *
     * @param username Identifiant de connexion
     * @param password Mot de passe en clair
     * @param requiredGroup Nom du groupe requis (ex: devops ou admins)
     * @return Résultat avec statut GROUP_NOT_AUTHORIZED si le groupe n'est pas présent
     */
    AuthenticationResult authenticate(String username, String password, String requiredGroup);

    /**
     * Authentifie un utilisateur en exigeant un ensemble de groupes (OU logique ou ET logique).
     */
    AuthenticationResult authenticate(String username, String password, Set<String> requiredGroups, boolean matchAll);

    /**
     * Permet à l'utilisateur de modifier son propre mot de passe en fournissant l'ancien.
     * Met à jour la date de dernier changement (shadowLastChange) et retire le drapeau de réinitialisation requise.
     */
    void changePassword(String username, String oldPassword, String newPassword);

    /**
     * Réinitialisation administrative du mot de passe (sans exiger l'ancien mot de passe).
     *
     * @param username Identifiant du compte
     * @param newPassword Nouveau mot de passe temporaire ou définitif
     * @param forceChangeAtNextLogin Si true, impose le changement immédiat dès la prochaine connexion
     */
    void adminResetPassword(String username, String newPassword, boolean forceChangeAtNextLogin);

    /**
     * Vérifie si un utilisateur a l'obligation de changer son mot de passe
     * (soit parce qu'il a expiré selon shadowMax, soit parce qu'une réinitialisation est requise via shadowLastChange=0 ou pwdReset=TRUE).
     */
    boolean isPasswordChangeRequired(String username);

    /**
     * Déclenche une demande de renouvellement obligatoire du mot de passe au prochain login
     * (positionne shadowLastChange à 0, convention standard PAM / Linux).
     */
    void requestPasswordReset(String username);

    /**
     * Récupère les informations détaillées d'un compte utilisateur.
     */
    LdapUser getUser(String username);

    /**
     * Vérifie si un compte utilisateur existe dans l'annuaire.
     */
    boolean userExists(String username);

    /**
     * Crée un nouvel utilisateur avec ses groupes et sa politique d'expiration.
     *
     * @param user Données de l'utilisateur (identifiant, uid/gid Unix, répertoires, etc.)
     * @param initialPassword Mot de passe initial
     * @param passwordMaxDays Durée de validité maximale en jours (ex: 90) ou null pour illimité
     * @param forceChangeAtNextLogin Si true, l'utilisateur devra changer son mdp dès la première connexion
     */
    void createUser(LdapUser user, String initialPassword, Integer passwordMaxDays, boolean forceChangeAtNextLogin);

    /**
     * Supprime définitivement un compte de l'annuaire.
     *
     * @param username Identifiant de l'utilisateur à supprimer
     * @param removeFromGroups Si true, retire également les références de l'utilisateur dans tous ses groupes
     */
    void deleteUser(String username, boolean removeFromGroups);

    /**
     * Met à jour les attributs d'un utilisateur existant (nom, prénom, email, shell, etc.).
     */
    void updateUser(LdapUser user);

    /**
     * Ajoute un utilisateur à un groupe (posixGroup ou groupOfNames).
     */
    void addUserToGroup(String username, String groupName);

    /**
     * Retire un utilisateur d'un groupe.
     */
    void removeUserFromGroup(String username, String groupName);

    /**
     * Retourne la liste des noms de groupes auxquels appartient l'utilisateur.
     */
    Set<String> getUserGroups(String username);

    /**
     * Crée un groupe (posixGroup ou groupOfNames).
     */
    void createGroup(String groupName, Long gidNumber, String description);

    /**
     * Déverrouille un compte verrouillé suite à de trop nombreuses tentatives.
     */
    void unlockAccount(String username);

    /**
     * Récupère la liste de tous les utilisateurs de l'OU.
     */
    List<LdapUser> listUsers();
}
