package com.lab.ldap.config;

/**
 * Type de gestion des appartenances aux groupes dans l'annuaire LDAP.
 */
public enum GroupType {
    /**
     * Groupes POSIX (RFC 2307) utilisant 'objectClass: posixGroup'
     * Les membres sont stockés dans l'attribut multi-valué 'memberUid' (login Unix).
     */
    POSIX_GROUP,

    /**
     * Groupes standards LDAP utilisant 'objectClass: groupOfNames' ou 'groupOfUniqueNames'
     * Les membres sont stockés sous forme de DN complets dans 'member' ou 'uniqueMember'.
     */
    GROUP_OF_NAMES,

    /**
     * Détection dynamique automatique selon l'objectClass présent sur le groupe.
     */
    AUTO_DETECT
}
