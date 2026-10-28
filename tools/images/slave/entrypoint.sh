#!/bin/bash
set -eo pipefail

echo "=========================================================="
echo " Starting CentOS 7 OpenLDAP Slave Node..."
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
LDAP_MASTER_HOST="${LDAP_MASTER_HOST:-ldap-master}"
LDAP_PORT="${LDAP_PORT:-389}"
SYNCREPL_RID="${SYNCREPL_RID:-001}"
SYNCREPL_RETRY="${SYNCREPL_RETRY:-5 5 300 5}"
SYNCREPL_TYPE="${SYNCREPL_TYPE:-refreshAndPersist}"
NSLCD_LDAP_URI="${NSLCD_LDAP_URI:-ldap://127.0.0.1:389}"

export LDAP_BASE_DN LDAP_DOMAIN_COMPONENT LDAP_ORGANIZATION
export LDAP_USERS_OU LDAP_GROUPS_OU LDAP_USERS_OU_DN LDAP_GROUPS_OU_DN
export LDAP_ADMIN_DN LDAP_ADMIN_PASSWORD LDAP_REPLICATOR_DN LDAP_REPLICATOR_PASSWORD
export LDAP_MASTER_HOST LDAP_PORT SYNCREPL_RID SYNCREPL_RETRY SYNCREPL_TYPE
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
if [ ! -f /var/lib/ldap/.slave_initialized ]; then
    echo "[Slave Init] Initializing Slave OpenLDAP database for the first time..."

    # Ensure DB_CONFIG is in place
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
    echo "[Slave Init] Starting temporary slapd for OLC provisioning..."
    /usr/sbin/slapd -u ldap -h "ldapi:///"
    
    # Wait for IPC socket
    for i in {1..30}; do
        if ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=config" dn >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
    done

    echo "[Slave Init] Loading standard schemas (cosine, nis, inetorgperson)..."
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif || true
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif || true
    ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif || true

    echo "[Slave Init] Generating administrator password hash..."
    LDAP_ADMIN_PASSWORD_HASH=$(slappasswd -s "${LDAP_ADMIN_PASSWORD}")

    echo "[Slave Init] Configuring database suffix, rootDN, replication consumer (syncrepl) and update referral..."
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
add: olcSyncrepl
olcSyncrepl: {0}rid=${SYNCREPL_RID} provider=ldap://${LDAP_MASTER_HOST}:${LDAP_PORT} type=${SYNCREPL_TYPE} retry="${SYNCREPL_RETRY}" searchbase="${LDAP_BASE_DN}" scope=sub schemachecking=on bindmethod=simple binddn="${LDAP_REPLICATOR_DN}" credentials="${LDAP_REPLICATOR_PASSWORD}"
-
add: olcUpdateRef
olcUpdateRef: ldap://${LDAP_MASTER_HOST}:${LDAP_PORT}
-
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange by self write by anonymous auth by dn.base="${LDAP_ADMIN_DN}" write by * none
-
add: olcAccess
olcAccess: {1}to dn.base="" by * read
-
add: olcAccess
olcAccess: {2}to * by dn.base="${LDAP_ADMIN_DN}" write by * read
EOF

    # Stop temporary slapd
    echo "[Slave Init] Stopping temporary slapd..."
    pkill -TERM -u ldap slapd || true
    sleep 1

    touch /var/lib/ldap/.slave_initialized
    echo "[Slave Init] Slave initialization complete!"
fi

# 4. Process supervision and execution
SLAPD_PID=""
NSLCD_PID=""

shutdown_services() {
    echo "[Slave] Signal received, shutting down gracefully..."
    if [ -n "$NSLCD_PID" ] && kill -0 "$NSLCD_PID" 2>/dev/null; then
        kill -TERM "$NSLCD_PID" 2>/dev/null || true
    fi
    if [ -n "$SLAPD_PID" ] && kill -0 "$SLAPD_PID" 2>/dev/null; then
        kill -TERM "$SLAPD_PID" 2>/dev/null || true
    fi
    wait "$NSLCD_PID" 2>/dev/null || true
    wait "$SLAPD_PID" 2>/dev/null || true
    echo "[Slave] All processes terminated."
    exit 0
}

trap shutdown_services SIGTERM SIGINT

echo "[Slave] Launching OpenLDAP slapd..."
/usr/sbin/slapd -u ldap -h "ldapi:/// ldap://0.0.0.0:389/" -d 256 >> /var/log/slapd.log 2>&1 &
SLAPD_PID=$!

echo "[Slave] Waiting for slapd to become responsive on port 389..."
for i in {1..60}; do
    if ldapsearch -x -H ldap://127.0.0.1:389 -b "" -s base >/dev/null 2>&1; then
        echo "[Slave] slapd is ready and listening on port 389."
        break
    fi
    sleep 0.5
done

echo "[Slave] Launching nslcd..."
/usr/sbin/nslcd -d >> /var/log/nslcd.log 2>&1 &
NSLCD_PID=$!

echo "[Slave] Waiting for nslcd socket..."
for i in {1..30}; do
    if [ -S /var/run/nslcd/socket ]; then
        echo "[Slave] nslcd socket is ready."
        break
    fi
    sleep 0.5
done

echo "[Slave] Services are operational. Monitoring processes..."
sleep infinity
# Main supervision loop
while true; do
    if ! kill -0 "$SLAPD_PID" 2>/dev/null; then
        echo "[Slave ERROR] slapd died unexpectedly! Showing last 30 lines of /var/log/slapd.log:"
        tail -n 30 /var/log/slapd.log || true
        exit 1
    fi
    if ! kill -0 "$NSLCD_PID" 2>/dev/null; then
        echo "[Slave ERROR] nslcd died unexpectedly! Showing last 30 lines of /var/log/nslcd.log:"
        tail -n 30 /var/log/nslcd.log || true
        exit 1
    fi
    sleep 2
done
