package oap.ws.security.server;

import oap.ws.security.Organization;
import oap.ws.security.User;

import java.util.List;
import java.util.Optional;

interface OrganizationWSI {

    Organization store( Organization organization );

    List<Organization> getAllOrganizations();

    Optional<Organization> getOrganization( String organizationId, User user );

    void removeOrganization( String organizationId );

    List<User> getAllUsers();

    User storeUser( User storeUser, String organizationId, User user );

    Optional<User> getUser( String organizatinoId, String email, User user );

    void removeUser( String organizationId, String email, User user );
}
