package oap.ws.security.server;

import oap.testng.Env;
import oap.util.Hash;
import oap.ws.security.AuthService;
import oap.ws.security.DefaultUser;
import oap.ws.security.LogoutWS;
import oap.ws.security.PasswordHasher;
import oap.ws.security.Role;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

public class LogoutWSTest {

    private static final String SALT = "test";

    private UserStorage userStorage;
    private AuthService authService;

    @BeforeClass
    public void startServer() {
        userStorage = new UserStorage( Env.tmpPath( "users" ) );
        authService = new AuthService( userStorage, new PasswordHasher( SALT ), 1 );
    }

    @Test
    public void testShouldLogoutExistingUser() {
        final DefaultUser user = new DefaultUser();
        user.email = "test@example.com";
        user.role = Role.ADMIN;
        user.password = Hash.sha256( SALT, "12345" );
        user.organizationId = "987654321";
        user.organizationName = "test";

        userStorage.store( user );

        final String id = authService.generateToken( user.email, "12345" ).get().id;

        assertNotNull( id );
        final LogoutWS loginWS = new LogoutWS( authService );

        loginWS.logout( user.email, user );

        assertFalse( authService.getToken( id ).isPresent() );
    }
}
