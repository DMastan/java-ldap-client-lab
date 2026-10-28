# Bibliothèque Java PAM / OpenLDAP (`pam-ldap-client`)

Bibliothèque Java moderne, performante et sans dépendance externe (100% Java SE standard via `javax.naming.ldap`), conçue pour s'interfacer avec OpenLDAP, PAM et NSS.

Elle permet d'authentifier les utilisateurs, de gérer les politiques de mots de passe (expiration, renouvellement forcé), les groupes POSIX / métier, et d'administrer le cycle de vie complet des comptes.

---

## 🚀 Fonctionnalités implémentées

- **Authentification & Contrôle d'accès :**
  - Authentification par mot de passe.
  - Réclamation d'un ou plusieurs groupes requis (`requiredGroup` ou `requiredGroups`).
  - Remontée du nombre de tentatives erronées préalables lors d'une connexion réussie.
- **Gestion des mots de passe & Politiques de sécurité :**
  - Changement de mot de passe par l'utilisateur (avec validation de l'ancien mot de passe).
  - Détection automatique de l'obligation de changer le mot de passe (`isPasswordChangeRequired`).
  - Demande administrative de renouvellement forcé au prochain login (`shadowLastChange: 0` conforme PAM).
  - Gestion de l'expiration du mot de passe en jours (`shadowMax`) et date calculée.
  - Hachage cryptographique sécurisé au standard OpenLDAP `{SSHA}` (Salted SHA-1).
- **Administration des comptes & Groupes (CRUD) :**
  - Création complète d'utilisateurs avec attributs POSIX (`uidNumber`, `gidNumber`, `homeDirectory`, `loginShell`), rattachement aux groupes et durée de validité du mot de passe.
  - Modification de compte (profil, appartenance aux groupes).
  - Suppression propre de compte (avec désaffiliation automatique des groupes).
  - Support natif des groupes POSIX (`memberUid`) et des groupes annuaire (`groupOfNames` avec `member`).

---

## 📦 Structure du projet

```
java-ldap-client/
├── pom.xml                                      # Configuration Maven (Java 11+)
├── README.md                                    # Documentation complète
├── target/
│   └── pam-ldap-client-1.0.0.jar                # JAR prêt à l'emploi (exécutable)
└── src/
    ├── main/
    │   ├── resources/
    │   │   └── ldap-client.properties           # Configuration externe
    │   └── java/com/lab/ldap/
    │       ├── config/
    │       │   ├── GroupType.java               # POSIX_GROUP, GROUP_OF_NAMES, AUTO_DETECT
    │       │   └── LdapConfig.java              # Configuration & Builder
    │       ├── model/
    │       │   ├── AuthStatus.java              # SUCCESS, INVALID_CREDENTIALS, GROUP_NOT_AUTHORIZED...
    │       │   ├── AuthenticationResult.java    # DTO résultat d'authentification
    │       │   ├── LdapGroup.java               # DTO groupe
    │       │   └── LdapUser.java                # DTO utilisateur riche
    │       ├── service/
    │       │   ├── LdapSecurityService.java     # Interface principale
    │       │   └── LdapSecurityServiceImpl.java # Implémentation JNDI
    │       ├── util/
    │       │   ├── LdapUtils.java               # Échappement anti-injection, calculs dates POSIX
    │       │   └── PasswordHasher.java          # Hachage SSHA conforme slappasswd
    │       └── example/
    │           └── LdapDemoApp.java             # Démonstration exécutable
```

---

## 🛠️ Compilation et Exécution du test de démonstration

### Avec Maven
```bash
cd java-ldap-client
mvn clean package
java -jar target/pam-ldap-client-1.0.0.jar
```

### Sans Maven (directement avec Java SE standard)
```powershell
# Compilation
javac -d target/classes $(Get-ChildItem -Path src/main/java -Filter *.java -Recurse | Select-Object -ExpandProperty FullName)

# Copie des propriétés
Copy-Item "src/main/resources/ldap-client.properties" -Destination "target/classes/"

# Exécution
java -cp "target/classes" com.lab.ldap.example.LdapDemoApp
```

---

## 💻 Exemples d'utilisation dans votre code Java

### 1. Initialiser le service

```java
// Option A : Depuis un fichier de configuration .properties
LdapConfig config = LdapConfig.loadFromFile("ldap-client.properties");

// Option B : Programmatique (idéal pour Spring Boot ou injecteurs de dépendances)
LdapConfig config = LdapConfig.builder()
        .host("ldap-master")               // Hôte (ou 127.0.0.1 depuis l'extérieur)
        .port(389)
        .baseDn("dc=lab,dc=example,dc=org")
        .adminDn("cn=admin,dc=lab,dc=example,dc=org")
        .adminPassword("AdminSecretPassword123!")
        .build();

LdapSecurityService ldapService = new LdapSecurityServiceImpl(config);
```

---

### 2. Authentification avec groupe requis et remontée des échecs

```java
// Authentification avec réclamation du groupe "devops"
AuthenticationResult result = ldapService.authenticate("toto", "MonMotDePasse123!", "devops");

if (result.isSuccess()) {
    System.out.println("Authentification réussie pour : " + result.getUser().getCommonName());
    
    // Remontée du nombre de tentatives incorrectes préalables
    int failedAttempts = result.getFailedAttemptsBeforeSuccess();
    if (failedAttempts > 0) {
        System.out.println("Avertissement : " + failedAttempts + " tentative(s) échouée(s) avant ce succès !");
    }

    // Vérification si le mot de passe doit être changé
    if (result.isPasswordChangeRequired()) {
        System.out.println("Action requise : Vous devez renouveler votre mot de passe.");
    }
} else {
    switch (result.getStatus()) {
        case INVALID_CREDENTIALS:
            System.err.println("Mot de passe incorrect.");
            break;
        case GROUP_NOT_AUTHORIZED:
            System.err.println("Accès refusé : vous ne possédez pas le groupe requis.");
            break;
        case ACCOUNT_LOCKED:
            System.err.println("Compte verrouillé.");
            break;
        default:
            System.err.println("Erreur : " + result.getErrorMessage());
    }
}
```

---

### 3. Changement et réinitialisation de mot de passe

```java
// Par l'utilisateur (fournit l'ancien mot de passe)
ldapService.changePassword("toto", "AncienMdp123!", "NouveauMdp456!");

// Demande administrative de renouvellement au prochain login (shadowLastChange = 0)
ldapService.requestPasswordReset("toto");

// Réinitialisation forcée par l'administrateur
ldapService.adminResetPassword("toto", "MdpTemporaire789!", true);
```

---

### 4. Création d'un utilisateur complet avec groupes et expiration

```java
LdapUser user = LdapUser.builder("martin")
        .givenName("Martin")
        .surname("Dupuis")
        .mail("martin.dupuis@example.org")
        .loginShell("/bin/bash")
        .group("devops")
        .group("developers")
        .build();

// Création avec mot de passe initial, expiration dans 90 jours, pas de changement forcé
ldapService.createUser(user, "InitPass123!", 90, false);
```

---

### 5. Modification et suppression

```java
// Ajout / Retrait de groupe
ldapService.addUserToGroup("martin", "admins");
ldapService.removeUserFromGroup("martin", "developers");

// Mise à jour d'attributs
LdapUser current = ldapService.getUser("martin");
current.setMail("martin.new@example.org");
current.setLoginShell("/bin/zsh");
ldapService.updateUser(current);

// Suppression définitive (avec retrait automatique des groupes)
ldapService.deleteUser("martin", true);
```

---

## 🔧 Comment adapter la bibliothèque à une base personnalisée ?

Chaque organisation possède des conventions d'annuaire spécifiques. Cette bibliothèque a été conçue pour s'y adapter sans modifier le code source :

### 1. Mapping d'arborescence et d'attributs via `LdapConfig`

| Propriété | Défaut (OpenLDAP / PAM) | Exemple Active Directory | Exemple Base Custom |
| :--- | :--- | :--- | :--- |
| `ldap.baseDn` | `dc=lab,dc=example,dc=org` | `dc=corp,dc=local` | `dc=monentreprise,dc=fr` |
| `ldap.usersOu` | `ou=users` | `cn=Users` | `ou=collaborateurs,ou=identites` |
| `ldap.groupsOu` | `ou=groups` | `cn=Groups` | `ou=roles` |
| `ldap.attribute.user` | `uid` | `sAMAccountName` | `mail` ou `employeeNumber` |
| `ldap.attribute.group` | `cn` | `cn` | `cn` |
| `ldap.attribute.posixMember` | `memberUid` | Non utilisé | `memberUid` |
| `ldap.attribute.dnMember` | `member` | `member` | `uniqueMember` |

### 2. Prise en charge des différents formats de groupes

La bibliothèque supporte 3 modes de groupes via `GroupType` :
- **`GroupType.POSIX_GROUP`** : Pour les groupes Unix POSIX (`objectClass: posixGroup`), les membres sont inscrits sous leur identifiant court (`memberUid: toto`).
- **`GroupType.GROUP_OF_NAMES`** : Pour les groupes LDAP standards (`objectClass: groupOfNames` ou `groupOfUniqueNames`), les membres sont enregistrés avec leur DN complet (`member: uid=toto,ou=users,dc=...`).
- **`GroupType.AUTO_DETECT` (Recommandé)** : La bibliothèque inspecte automatiquement la classe du groupe pour choisir la bonne stratégie.

### 3. Gestion de la politique de sécurité des mots de passe

- **Sous Linux / PAM (RFC 2307 - `shadowAccount`)** :
  - `shadowLastChange = 0` : Indique immédiatement à la couche PAM (`pam_unix`, `pam_ldap`) que le mot de passe est expiré et doit être renouvelé (`PAM_NEW_AUTHTOK_REQD`).
  - `shadowMax` : Nombre maximal de jours de validité.
- **Sous OpenLDAP avec module `ppolicy`** :
  - Si l'overlay `ppolicy` est activé, l'annuaire maintient les attributs opérationnels `pwdFailureTime`, `pwdAccountLockedTime` et `pwdReset`.
  - La bibliothèque les lit automatiquement s'ils existent et s'adapte sans rupture si `ppolicy` n'est pas chargé.

---

## 🐳 Déploiement et intégration dans un conteneur Docker

### Dans le même conteneur que votre nœud LDAP :
1. Copiez le fichier `target/pam-ldap-client-1.0.0.jar` dans le conteneur.
2. Utilisez l'adresse locale `127.0.0.1:389` dans `ldap-client.properties`.

### Dans un conteneur applicatif dédié (ex: Spring Boot / Quarkus) :
1. Déclarez votre conteneur applicatif sur le réseau Docker `ldap-net` dans `compose.yaml`.
2. Configurez l'URL LDAP avec le nom de service :
   ```properties
   ldap.host=ldap-master
   ldap.port=389
   ```
3. Pour la haute disponibilité, vous pouvez diriger les opérations de lecture/authentification vers `ldap-slave:389` et les opérations d'écriture (`createUser`, `changePassword`, `deleteUser`) vers `ldap-master:389`.
