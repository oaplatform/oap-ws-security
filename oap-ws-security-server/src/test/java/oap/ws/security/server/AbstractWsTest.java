package oap.ws.security.server;

import oap.application.Kernel;
import oap.concurrent.SynchronizedThread;
import oap.http.PlainHttpListener;
import oap.http.Server;
import oap.http.cors.GenericCorsPolicy;
import oap.json.schema.TestJsonValidators;
import oap.testng.AbstractTest;
import oap.testng.Env;
import oap.util.Lists;
import oap.ws.SessionManager;
import oap.ws.WebServices;
import oap.ws.WsConfig;
import oap.ws.security.AuthService;
import oap.ws.security.PasswordHasher;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;

import static java.util.Collections.emptyList;
import static oap.http.testng.HttpAsserts.reset;

/**
 * Created by igor.petrenko on 31.10.2017.
 */
public abstract class AbstractWsTest extends AbstractTest {
    protected static final String SALT = "test";

    protected final Server server = new Server( 100 );
    protected WebServices webServices;
    protected UserStorage userStorage;
    protected SynchronizedThread listener;
    protected AuthService authService;
    private Kernel kernel;
    private final String conf;

    protected AbstractWsTest( String conf ) {
        this.conf = conf;
    }

    @BeforeClass
    public void beforeClass() {
        kernel = new Kernel( emptyList() );
        kernel.start();

        userStorage = new UserStorage( Env.tmpPath( "users" ) );

        authService = new AuthService( userStorage, new PasswordHasher( "test" ), 1 );

        webServices = new WebServices( server, new SessionManager( 10, null, "/" ),
            new GenericCorsPolicy( "*", "Authorization", true, Lists.of( "POST", "GET" ) ),
            TestJsonValidators.jsonValidatos(),
            WsConfig.CONFIGURATION.fromResource( getClass(), conf ) );

        listener = new SynchronizedThread( new PlainHttpListener( server, Env.port() ) );
        listener.start();
    }

    @AfterClass
    @Override
    public void afterClass() throws Exception {
        listener.stop();
        server.stop();
        webServices.stop();
        reset();

        userStorage.close();

        kernel.stop();
    }

    @BeforeMethod
    @Override
    public void beforeMethod() throws Exception {
        super.beforeMethod();

        userStorage.clear();
    }
}
