package oap.ws.security.server;

import lombok.EqualsAndHashCode;
import lombok.ToString;
import oap.ws.security.Role;
import oap.ws.security.User;

/**
 * Created by igor.petrenko on 05.10.2017.
 */
@EqualsAndHashCode
@ToString
public class DefaultUser implements User {
    private static final long serialVersionUID = 7717142374765357180L;
    public String email;
    public String password;
    public Role role;
    public String organizationId;
    public String organizationName;

    public DefaultUser() {
    }

    public DefaultUser( Role role, String organizationId, String email ) {
        this.role = role;
        this.organizationId = organizationId;
        this.email = email;
    }

    @Override
    public String getEmail() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Role getRole() {
        return role;
    }

    @Override
    public String getOrganization() {
        return organizationId;
    }
}
