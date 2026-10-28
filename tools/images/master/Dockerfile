FROM centos:7

LABEL role="ldap-master" \
      maintainer="DevOps Lab <devops@lab.example.org>" \
      description="CentOS 7 OpenLDAP Master Server with PAM/NSS client integration"

# 1. Archive repositories for CentOS 7 EOL
COPY images/base/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo

# 2. Install OpenLDAP, PAM, NSS, and system utilities
RUN yum clean all && \
    yum makecache && \
    yum install -y \
        openldap \
        openldap-servers \
        openldap-clients \
        nss-pam-ldapd \
        pam \
        pam-devel \
        gcc \
        make \
        which \
        procps-ng \
        iproute \
        bind-utils \
        gettext \
        util-linux \
        shadow-utils && \
    yum clean all && \
    rm -rf /var/cache/yum

# 3. Build the PAM authentication diagnostic utility
COPY src/pam_auth_check.c /tmp/pam_auth_check.c
RUN gcc -std=c99 -O2 /tmp/pam_auth_check.c -lpam -o /usr/local/bin/pam_auth_check && \
    chmod 755 /usr/local/bin/pam_auth_check && \
    rm -f /tmp/pam_auth_check.c

# 4. Create runtime directories and permissions
RUN mkdir -p /var/run/nslcd /var/run/openldap /etc/openldap/slapd.d /var/lib/ldap /scripts /config && \
    chown -R ldap:ldap /var/run/openldap /etc/openldap/slapd.d /var/lib/ldap && \
    chown -R nslcd:ldap /var/run/nslcd

# 5. Master Entrypoint
COPY images/master/entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh

WORKDIR /root
EXPOSE 389

ENTRYPOINT ["/entrypoint.sh"]
