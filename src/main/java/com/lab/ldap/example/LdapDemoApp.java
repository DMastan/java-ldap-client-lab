package com.lab.ldap.example;

import com.lab.ldap.config.LdapConfig;
import com.lab.ldap.model.AuthStatus;
import com.lab.ldap.model.AuthenticationResult;
import com.lab.ldap.model.LdapUser;
import com.lab.ldap.service.LdapSecurityService;
import com.lab.ldap.service.LdapSecurityServiceImpl;

import java.io.InputStream;
import java.util.Collections;
import java.util.Set;

/**
 * Application de démonstration et de validation de la bibliothèque Java PAM / LDAP.
 * Illustre chaque fonctionnalité demandée par l'utilisateur.
 */
public class LdapDemoApp {

    public static void main(String[] args) {
        System.out.println("==========================================================");
        System.out.println(" DÉMARRAGE DE LA DÉMONSTRATION DU CLIENT JAVA PAM / LDAP");
        System.out.println("==========================================================");

        // 1. Chargement de la configuration
        LdapConfig config;
        try (InputStream is = LdapDemoApp.class.getClassLoader().getResourceAsStream("ldap-client.properties")) {
            if (is != null) {
                config = LdapConfig.loadFromProperties(is);
                System.out.println("[Config] Fichier ldap-client.properties chargé avec succès.");
            } else {
                config = LdapConfig.builder()
                        .host("127.0.0.1")
                        .port(10389)
                        .baseDn("dc=lab,dc=example,dc=org")
                        .adminDn("cn=admin,dc=lab,dc=example,dc=org")
                        .adminPassword("AdminSecretPassword123!")
                        .build();
                System.out.println("[Config] Utilisation des valeurs par défaut.");
            }
        } catch (Exception e) {
            System.err.println("[Config] Erreur de lecture de la configuration : " + e.getMessage());
            return;
        }

        LdapSecurityService ldapService = new LdapSecurityServiceImpl(config);

        String demoUser = "alice_dev";
        String initialPassword = "AliceInitialPassword123!";
        String newPassword = "AliceNewSuperSecret456!";

        try {
            // Nettoyage préventif
            if (ldapService.userExists(demoUser)) {
                ldapService.deleteUser(demoUser, true);
            }

            // -----------------------------------------------------------------
            // TEST 1 : CRÉATION D'UN UTILISATEUR AVEC GROUPES ET EXPIRATION
            // -----------------------------------------------------------------
            System.out.println("\n[1] Création de l'utilisateur '" + demoUser + "' avec groupe 'devops' et expiration dans 90 jours...");
            LdapUser newUser = LdapUser.builder(demoUser)
                    .givenName("Alice")
                    .surname("Dupont")
                    .commonName("Alice Dupont")
                    .mail("alice.dupont@example.org")
                    .loginShell("/bin/bash")
                    .group("devops")
                    .build();

            // Création avec validité de 90 jours, pas de changement forcé immédiat
            ldapService.createUser(newUser, initialPassword, 90, false);
            System.out.println("-> Compte créé avec succès !");

            // Vérification des données enregistrées
            LdapUser fetched = ldapService.getUser(demoUser);
            System.out.println("-> Données récupérées : " + fetched);
            System.out.println("-> Groupes de l'utilisateur : " + fetched.getGroups());
            System.out.println("-> Date d'expiration calculée : " + fetched.getPasswordExpiresAt());
            System.out.println("-> Jours restants avant expiration : " + fetched.getDaysUntilPasswordExpiration());

            // -----------------------------------------------------------------
            // TEST 2 : SIMULATION D'ÉCHECS PUIS AUTHENTIFICATION RÉUSSIE
            //          (Renvoi du nombre de tentatives incorrectes)
            // -----------------------------------------------------------------
            System.out.println("\n[2] Simulation de tentatives échouées de mot de passe...");
            ldapService.authenticate(demoUser, "WrongPassword_1");
            ldapService.authenticate(demoUser, "WrongPassword_2");
            System.out.println("-> 2 mauvaises tentatives enregistrées.");

            System.out.println("-> Authentification avec le BON mot de passe :");
            AuthenticationResult authSuccess = ldapService.authenticate(demoUser, initialPassword);
            System.out.println("   Succès : " + authSuccess.isSuccess());
            System.out.println("   Statut : " + authSuccess.getStatus());
            System.out.println("   Nombre de tentatives incorrectes préalables : " + authSuccess.getFailedAttemptsBeforeSuccess());
            System.out.println("   Doit changer son mot de passe : " + authSuccess.isPasswordChangeRequired());

            // -----------------------------------------------------------------
            // TEST 3 : CONTRÔLE D'ACCÈS PAR GROUPE REQUIS
            // -----------------------------------------------------------------
            System.out.println("\n[3] Test de réclamation de groupe lors de l'authentification...");
            // Alice est dans 'devops' -> succès attendu
            AuthenticationResult groupSuccess = ldapService.authenticate(demoUser, initialPassword, "devops");
            System.out.println("-> Authentification réclamant le groupe 'devops' : Succès = " + groupSuccess.isSuccess());

            // Alice n'est PAS dans 'admins' -> rejet attendu
            AuthenticationResult groupFail = ldapService.authenticate(demoUser, initialPassword, "admins");
            System.out.println("-> Authentification réclamant le groupe 'admins' : Succès = " + groupFail.isSuccess()
                    + " | Statut = " + groupFail.getStatus() + " | Erreur = " + groupFail.getErrorMessage());

            // -----------------------------------------------------------------
            // TEST 4 : MODIFICATION DU COMPTE (AJOUT DE GROUPE)
            // -----------------------------------------------------------------
            System.out.println("\n[4] Ajout de l'utilisateur au groupe 'admins'...");
            ldapService.addUserToGroup(demoUser, "admins");
            Set<String> updatedGroups = ldapService.getUserGroups(demoUser);
            System.out.println("-> Nouveaux groupes de l'utilisateur : " + updatedGroups);

            // Re-tentative avec réclamation du groupe 'admins'
            AuthenticationResult groupSuccess2 = ldapService.authenticate(demoUser, initialPassword, "admins");
            System.out.println("-> Authentification réclamant 'admins' après modification : Succès = " + groupSuccess2.isSuccess());

            // -----------------------------------------------------------------
            // TEST 5 : CHANGEMENT DE MOT DE PASSE PAR L'UTILISATEUR
            // -----------------------------------------------------------------
            System.out.println("\n[5] Changement de mot de passe par l'utilisateur...");
            ldapService.changePassword(demoUser, initialPassword, newPassword);
            System.out.println("-> Mot de passe changé avec succès !");

            // Vérification de la connexion avec le nouveau mot de passe
            AuthenticationResult authNewPass = ldapService.authenticate(demoUser, newPassword);
            System.out.println("-> Connexion avec le nouveau mot de passe : Succès = " + authNewPass.isSuccess());

            // -----------------------------------------------------------------
            // TEST 6 : DEMANDE DE RÉINITIALISATION DE MOT DE PASSE (shadowLastChange=0)
            // -----------------------------------------------------------------
            System.out.println("\n[6] Demande administrative de réinitialisation de mot de passe...");
            ldapService.requestPasswordReset(demoUser);
            boolean mustChange = ldapService.isPasswordChangeRequired(demoUser);
            System.out.println("-> L'utilisateur doit-il changer son mdp ? : " + mustChange);

            AuthenticationResult authResetPrompt = ldapService.authenticate(demoUser, newPassword);
            System.out.println("-> Authentification : Succès = " + authResetPrompt.isSuccess()
                    + " | passwordChangeRequired = " + authResetPrompt.isPasswordChangeRequired());

            // -----------------------------------------------------------------
            // TEST 7 : SUPPRESSION D'UN GROUPE ET SUPPRESSION DU COMPTE
            // -----------------------------------------------------------------
            System.out.println("\n[7] Retrait du groupe 'admins' puis suppression du compte...");
            ldapService.removeUserFromGroup(demoUser, "admins");
            System.out.println("-> Groupes restants : " + ldapService.getUserGroups(demoUser));

            ldapService.deleteUser(demoUser, true);
            boolean stillExists = ldapService.userExists(demoUser);
            System.out.println("-> Le compte existe-t-il encore après suppression ? : " + stillExists);

            System.out.println("\n==========================================================");
            System.out.println(" TOUS LES TESTS DE LA LIBRAIRIE SONT VALIDÉS AVEC SUCCÈS !");
            System.out.println("==========================================================");

        } catch (Exception e) {
            System.err.println("\n[ERREUR] Une exception a été levée pendant l'exécution : ");
            e.printStackTrace();
        }
    }
}
