package com.lab.ldap.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utilitaire cryptographique pour la gestion des mots de passe OpenLDAP.
 * Génère et valide les empreintes SSHA (Salted SHA-1), format standard d'OpenLDAP (slappasswd).
 */
public class PasswordHasher {

    private static final String SSHA_PREFIX = "{SSHA}";
    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Hache un mot de passe au format standard {SSHA}.
     *
     * @param password Mot de passe en clair
     * @return Chaîne commençant par {SSHA} compatible avec l'attribut userPassword d'OpenLDAP
     */
    public static String hashSSHA(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Le mot de passe ne peut pas être nul");
        }

        byte[] salt = new byte[8];
        RANDOM.nextBytes(salt);

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(password.getBytes(StandardCharsets.UTF_8));
            md.update(salt);
            byte[] digest = md.digest();

            // Concaténer digest (20 octets) + salt (8 octets)
            byte[] digestAndSalt = new byte[digest.length + salt.length];
            System.arraycopy(digest, 0, digestAndSalt, 0, digest.length);
            System.arraycopy(salt, 0, digestAndSalt, digest.length, salt.length);

            return SSHA_PREFIX + Base64.getEncoder().encodeToString(digestAndSalt);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Algorithme SHA-1 non supporté par la JVM", e);
        }
    }

    /**
     * Vérifie la concordance entre un mot de passe en clair et un hash {SSHA}.
     */
    public static boolean verifySSHA(String password, String sshaHash) {
        if (password == null || sshaHash == null) {
            return false;
        }

        if (!sshaHash.startsWith(SSHA_PREFIX)) {
            // Si le mot de passe dans l'annuaire est en clair
            return password.equals(sshaHash);
        }

        try {
            String base64Data = sshaHash.substring(SSHA_PREFIX.length());
            byte[] digestAndSalt = Base64.getDecoder().decode(base64Data);

            if (digestAndSalt.length <= 20) {
                return false; // Longueur minimale d'un SHA-1 (20 octets) + sel
            }

            byte[] digest = Arrays.copyOfRange(digestAndSalt, 0, 20);
            byte[] salt = Arrays.copyOfRange(digestAndSalt, 20, digestAndSalt.length);

            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(password.getBytes(StandardCharsets.UTF_8));
            md.update(salt);
            byte[] computedDigest = md.digest();

            return MessageDigest.isEqual(digest, computedDigest);
        } catch (Exception e) {
            return false;
        }
    }
}
