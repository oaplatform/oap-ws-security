package oap.ws.security.server;

import oap.ws.security.Organization;
import oap.ws.security.User;

import java.util.List;
import java.util.Optional;

interface OrganizationWSI {

    Organization store( Organization organization );

    List<Organization> list();

    Optional<Organization> organization( String organizationId, User user );

    void delete( String organizationId );

    List<User> users( String organizationId );

    User userStore( User storeUser, String organizationId, User user );

    Optional<User> user( String organizatinoId, String email, User user );

    void userDelete( String organizationId, String email, User user );
}
