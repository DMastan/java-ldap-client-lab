FROM centos:7

LABEL maintainer="DevOps Lab <devops@lab.example.org>" \
      description="CentOS 7 Base Image with OpenLDAP, nslcd, PAM and NSS client tools"

# 1. Update repositories to vault.centos.org for CentOS 7 EOL compatibility
COPY images/base/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo

# 2. Install required packages
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

# 3. Compile the standalone PAM authentication tester utility
COPY src/pam_auth_check.c /tmp/pam_auth_check.c
RUN gcc -O2 /tmp/pam_auth_check.c -lpam -o /usr/local/bin/pam_auth_check && \
    chmod 755 /usr/local/bin/pam_auth_check && \
    rm -f /tmp/pam_auth_check.c

# 4. Prepare directories and permissions
RUN mkdir -p /var/run/nslcd /var/run/openldap /etc/openldap/slapd.d /var/lib/ldap /scripts && \
    chown -R ldap:ldap /var/run/openldap /etc/openldap/slapd.d /var/lib/ldap && \
    chown -R nslcd:ldap /var/run/nslcd

WORKDIR /root
