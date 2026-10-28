package com.lab.ldap.model;

import com.lab.ldap.config.GroupType;
import java.util.HashSet;
import java.util.Set;

/**
 * Représente un groupe dans l'annuaire (posixGroup ou groupOfNames).
 */
public class LdapGroup {

    private String name;
    private String dn;
    private Long gidNumber;
    private String description;
    private GroupType groupType = GroupType.POSIX_GROUP;
    private Set<String> members = new HashSet<>();

    public LdapGroup() {}

    public LdapGroup(String name) {
        this.name = name;
    }

    public LdapGroup(String name, Long gidNumber) {
        this.name = name;
        this.gidNumber = gidNumber;
        this.groupType = GroupType.POSIX_GROUP;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDn() { return dn; }
    public void setDn(String dn) { this.dn = dn; }

    public Long getGidNumber() { return gidNumber; }
    public void setGidNumber(Long gidNumber) { this.gidNumber = gidNumber; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public GroupType getGroupType() { return groupType; }
    public void setGroupType(GroupType groupType) { this.groupType = groupType; }

    public Set<String> getMembers() { return members; }
    public void setMembers(Set<String> members) { this.members = members != null ? members : new HashSet<>(); }

    @Override
    public String toString() {
        return "LdapGroup{" +
                "name='" + name + '\'' +
                ", gidNumber=" + gidNumber +
                ", type=" + groupType +
                ", members=" + members.size() +
                '}';
    }
}
