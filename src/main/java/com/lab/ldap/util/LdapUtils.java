package com.lab.ldap.util;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

/**
 * Utilitaires pour la manipulation des requêtes LDAP et le calcul des dates POSIX shadow.
 */
public class LdapUtils {

    private static final LocalDate EPOCH = LocalDate.of(1970, 1, 1);

    /**
     * Retourne le nombre de jours écoulés depuis l'epoch Unix (1er Janvier 1970).
     * Format utilisé par l'attribut shadowLastChange de shadowAccount (RFC 2307).
     */
    public static long getCurrentEpochDays() {
        return ChronoUnit.DAYS.between(EPOCH, LocalDate.now());
    }

    /**
     * Convertit un nombre de jours depuis l'epoch en LocalDate.
     */
    public static LocalDate epochDaysToLocalDate(long days) {
        return EPOCH.plusDays(days);
    }

    /**
     * Échappe les caractères réservés dans un filtre de recherche LDAP (RFC 4515)
     * pour prévenir les injections LDAP.
     */
    public static String escapeLdapFilter(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\': sb.append("\\5c"); break;
                case '*':  sb.append("\\2a"); break;
                case '(':  sb.append("\\28"); break;
                case ')':  sb.append("\\29"); break;
                case '\0': sb.append("\\00"); break;
                default:   sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Échappe les caractères réservés dans un composant de DN LDAP (RFC 4514).
     */
    public static String escapeDnComponent(String input) {
        if (input == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case ',':
                case '=':
                case '+':
                case '<':
                case '>':
                case '#':
                case ';':
                case '\\':
                case '"':
                    sb.append('\\').append(c);
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}
