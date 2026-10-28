#!/bin/bash
set -eo pipefail

echo "=========================================================="
echo " Starting CentOS 7 OpenLDAP Master Node..."
echo "=========================================================="

# 1. Environment variable defaults
LDAP_BASE_DN="${LDAP_BASE_DN:-dc=lab,dc=example,dc=org}"
LDAP_DOMAIN_COMPONENT="${LDAP_DOMAIN_COMPONENT:-lab}"
LDAP_ORGANIZATION="${LDAP_ORGANIZATION:-Lab DevOps}"
LDAP_USERS_OU="${LDAP_USERS_OU:-users}"
LDAP_GROUPS_OU="${LDAP_GROUPS_OU:-groups}"
LDAP_USERS_OU_DN="${LDAP_USERS_OU_DN:-ou=users,dc=lab,dc=example,dc=org}"
LDAP_GROUPS_OU_DN="${LDAP_GROUPS_OU_DN:-ou=groups,dc=lab,dc=example,dc=org}"
LDAP_ADMIN_DN="${LDAP_ADMIN_DN:-cn=admin,dc=lab,dc=example,dc=org}"
LDAP_ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD:-AdminSecretPassword123!}"
LDAP_REPLICATOR_DN="${LDAP_REPLICATOR_DN:-cn=replicator,dc=lab,dc=example,dc=org}"
LDAP_REPLICATOR_PASSWORD="${LDAP_REPLICATOR_PASSWORD:-ReplicatorSecret123!}"
NSLCD_LDAP_URI="${NSLCD_LDAP_URI:-ldap://127.0.0.1:389}"

export LDAP_BASE_DN LDAP_DOMAIN_COMPONENT LDAP_ORGANIZATION
export LDAP_USERS_OU LDAP_GROUPS_OU LDAP_USERS_OU_DN LDAP_GROUPS_OU_DN
export LDAP_ADMIN_DN LDAP_ADMIN_PASSWORD LDAP_REPLICATOR_DN LDAP_REPLICATOR_PASSWORD
export NSLCD_LDAP_URI

# 2. Configure PAM and NSS client stack
echo "[Config] Setting up NSS (/etc/nsswitch.conf)..."
if [ -f /config/nsswitch/nsswitch.conf ]; then
    cp /config/nsswitch/nsswitch.conf /etc/nsswitch.conf
fi

echo "[Config] Setting up PAM (/etc/pam.d/)..."
if [ -f /config/pam/system-auth ]; then
    cp /config/pam/system-auth /etc/pam.d/system-auth
fi
if [ -f /config/pam/password-auth ]; then
    cp /config/pam/password-auth /etc/pam.d/password-auth
fi
if [ -f /config/pam/pam_auth_check ]; then
    cp /config/pam/pam_auth_check /etc/pam.d/pam_auth_check
fi

echo "[Config] Setting up nslcd (/etc/nslcd.conf)..."
mkdir -p /var/run/nslcd
chown -R nslcd:ldap /var/run/nslcd
if [ -f /config/nslcd/nslcd.conf.template ]; then
    envsubst < /config/nslcd/nslcd.conf.template > /etc/nslcd.conf
    chmod 600 /etc/nslcd.conf
    chown nslcd:ldap /etc/nslcd.conf
fi

if [ -f /config/ldap/ldap.conf ]; then
    cp /config/ldap/ldap.conf /etc/openldap/ldap.conf
fi

# Ensure runtime directories exist
mkdir -p /var/run/openldap /var/lib/ldap /etc/openldap/slapd.d /var/log
chown -R ldap:ldap /var/run/openldap /var/lib/ldap /etc/openldap/slapd.d

# 3. First-time database initialization
if [ ! -f /var/lib/ldap/.master_initialized ]; then
    echo "[Master Init] Initializing Master OpenLDAP database for the first time..."

    # Ensure DB_CONFIG is in place for performance & transaction logs
    if [ ! -f /var/lib/ldap/DB_CONFIG ]; then
        cat << 'EOF' > /var/lib/ldap/DB_CONFIG
set_cachesize 0 2097152 1
set_lg_regionmax 262144
set_lg_bsize 2097152
set_flags DB_LOG_AUTOREMOVE
EOF
        chown ldap:ldap /var/lib/ldap/DB_CONFIG
    fi

    # Start temporary slapd with IPC socket only
    echo "[Master Init] Starting temporary slapd for OLC provisioning..."
    /usr/sbin/slapd -u ldap -h "ldapi:///"
    
    # Wait for IPC socket
    for i in {1..30}; do
        if ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=config" dn >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done

    echo "[Master Init] Loading standard schemas (cosine, nis, inetorgperson)..."
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif || true
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif || true
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif || true

    echo "[Master Init] Loading syncprov module..."
    ldapadd -Y EXTERNAL -H ldapi:/// << 'EOF' || true
dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib64/openldap
olcModuleLoad: syncprov.la
EOF

    echo "[Master Init] Generating administrator password hash..."
    LDAP_ADMIN_PASSWORD_HASH=$(slappasswd -s "${LDAP_ADMIN_PASSWORD}")

    echo "[Master Init] Configuring database suffix, rootDN, ACLs and replication indexes..."
    ldapmodify -Y EXTERNAL -H ldapi:/// << EOF
dn: olcDatabase={2}hdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: ${LDAP_BASE_DN}
-
replace: olcRootDN
olcRootDN: ${LDAP_ADMIN_DN}
-
replace: olcRootPW
olcRootPW: ${LDAP_ADMIN_PASSWORD_HASH}
-
add: olcDbIndex
olcDbIndex: entryUUID,entryCSN eq
-
add: olcDbIndex
olcDbIndex: uid,uidNumber,gidNumber,memberUid eq
-
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by self write by anonymous auth by dn.base="${LDAP_REPLICATOR_DN}" read by dn.base="${LDAP_ADMIN_DN}" write by * none
-
add: olcAccess
olcAccess: {1}to dn.base="" by * read
-
add: olcAccess
olcAccess: {2}to * by self write by dn.base="${LDAP_REPLICATOR_DN}" read by dn.base="${LDAP_ADMIN_DN}" write by * read
EOF

    echo "[Master Init] Activating syncprov overlay on database..."
    ldapadd -Y EXTERNAL -H ldapi:/// << 'EOF' || true
dn: olcOverlay=syncprov,olcDatabase={2}hdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcSyncProvConfig
olcOverlay: syncprov
olcSpCheckpoint: 100 10
olcSpSessionlog: 100
EOF

    # Stop temporary slapd
    echo "[Master Init] Stopping temporary slapd..."
    pkill -TERM -u ldap slapd || true
    sleep 1

    # Start slapd with normal listeners so ldapadd can authenticate
    /usr/sbin/slapd -u ldap -h "ldapi:/// ldap://0.0.0.0:389/"
    for i in {1..30}; do
        if ldapsearch -x -H ldap://127.0.0.1:389 -b "" -s base >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done

    echo "[Master Init] Populating base tree structure..."
    if [ -f /config/ldap/base.ldif.template ]; then
        envsubst < /config/ldap/base.ldif.template > /tmp/base.ldif
        ldapadd -x -D "${LDAP_ADMIN_DN}" -w "${LDAP_ADMIN_PASSWORD}" -f /tmp/base.ldif
        rm -f /tmp/base.ldif
    fi

    # Stop temporary server
    pkill -TERM -u ldap slapd || true
    sleep 1

    touch /var/lib/ldap/.master_initialized
    echo "[Master Init] Master initialization complete!"
fi

# 4. Process supervision and execution
SLAPD_PID=""
NSLCD_PID=""

shutdown_services() {
    echo "[Master] Signal received, shutting down gracefully..."
    if [ -n "$NSLCD_PID" ] && kill -0 "$NSLCD_PID" 2>/dev/null; then
        kill -TERM "$NSLCD_PID" 2>/dev/null || true
    fi
    if [ -n "$SLAPD_PID" ] && kill -0 "$SLAPD_PID" 2>/dev/null; then
        kill -TERM "$SLAPD_PID" 2>/dev/null || true
    fi
    wait "$NSLCD_PID" 2>/dev/null || true
    wait "$SLAPD_PID" 2>/dev/null || true
    echo "[Master] All processes terminated."
    exit 0
}

trap shutdown_services SIGTERM SIGINT

echo "[Master] Launching OpenLDAP slapd..."
/usr/sbin/slapd -u ldap -h "ldapi:/// ldap://0.0.0.0:389/" -d 256 >> /var/log/slapd.log 2>&1 &
SLAPD_PID=$!

echo "[Master] Waiting for slapd to become responsive on port 389..."
for i in {1..60}; do
    if ldapsearch -x -H ldap://127.0.0.1:389 -b "" -s base >/dev/null 2>&1; then
        echo "[Master] slapd is ready and listening on port 389."
        break
    fi
    sleep 0.5
done

echo "[Master] Launching nslcd..."
/usr/sbin/nslcd -d >> /var/log/nslcd.log 2>&1 &
NSLCD_PID=$!

echo "[Master] Waiting for nslcd socket..."
for i in {1..30}; do
    if [ -S /var/run/nslcd/socket ]; then
        echo "[Master] nslcd socket is ready."
        break
    fi
    sleep 0.5
done

echo "[Master] Services are operational. Monitoring processes..."
sleep infinity
# Main supervision loop
while true; do
    if ! kill -0 "$SLAPD_PID" 2>/dev/null; then
        echo "[Master ERROR] slapd died unexpectedly! Showing last 30 lines of /var/log/slapd.log:"
        tail -n 30 /var/log/slapd.log || true
        exit 1
    fi
    if ! kill -0 "$NSLCD_PID" 2>/dev/null; then
        echo "[Master ERROR] nslcd died unexpectedly! Showing last 30 lines of /var/log/nslcd.log:"
        tail -n 30 /var/log/nslcd.log || true
        exit 1
    fi
    sleep 2
done
