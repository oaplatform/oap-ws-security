package oap.ws.security.server;

import oap.ws.security.DefaultUser;
import oap.ws.security.User;

import java.util.List;
import java.util.Optional;

interface OrganizationWSI {

    Organization store( Organization organization );

    List<Organization> list();

    Optional<Organization> organization( String organizationId, DefaultUser user );

    void delete( String organizationId );

    List<? extends User> users( String organizationId );

    User userStore( DefaultUser storeUser, String organizationId, DefaultUser user );

    Optional<User> user( String organizatinoId, String email, User user );

    void userDelete( String organizationId, String email, User user );
}
