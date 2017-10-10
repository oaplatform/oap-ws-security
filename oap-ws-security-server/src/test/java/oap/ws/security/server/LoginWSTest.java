/*
 * The MIT License (MIT)
 *
 * Copyright (c) Open Application Platform Authors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package oap.ws.security.server;

import oap.application.Application;
import oap.concurrent.SynchronizedThread;
import oap.http.PlainHttpListener;
import oap.http.Server;
import oap.http.cors.GenericCorsPolicy;
import oap.testng.Env;
import oap.util.Hash;
import oap.util.Lists;
import oap.ws.SessionManager;
import oap.ws.WebServices;
import oap.ws.WsConfig;
import oap.ws.security.AuthService;
import oap.ws.security.LoginWS;
import oap.ws.security.Role;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import static oap.http.testng.HttpAsserts.HTTP_PREFIX;
import static oap.http.testng.HttpAsserts.assertGet;
import static oap.http.testng.HttpAsserts.reset;


public class LoginWSTest {

    private static final String SALT = "test";

    private final Server server = new Server( 100 );
    private final WebServices webServices = new WebServices( server, new SessionManager( 10, null, "/" ),
        new GenericCorsPolicy( "*", "Authorization", true, Lists.of( "POST", "GET" ) ),
        WsConfig.CONFIGURATION.fromResource( getClass(), "ws-login.conf" ) );

    private UserStorage userStorage;
    private AuthService authService;

    private SynchronizedThread listener;

    @BeforeClass
    public void startServer() {
        userStorage = new UserStorage( Env.tmpPath( "users" ) );
        authService = new AuthService( userStorage, 1, "test" );

        Application.register( "ws-login", new LoginWS( authService, null, 10 ) );

        webServices.start();
        listener = new SynchronizedThread( new PlainHttpListener( server, Env.port() ) );
        listener.start();
    }

    @AfterClass
    public void stopServer() {
        listener.stop();
        server.stop();
        webServices.stop();
        reset();
    }

    @BeforeMethod
    public void setUp() {
        userStorage.clear();
    }

    @Test
    public void testShouldNotLoginNonExistingUser() {
        assertGet( HTTP_PREFIX() + "/login/?email=test@example.com&password=12345" ).hasCode( 401 ).hasBody( "" );
    }

    @Test
    public void testShouldLoginExistingUser() {
        final DefaultUser user = new DefaultUser();
        user.email = "test@example.com";
        user.role = Role.ADMIN;
        user.password = Hash.sha256( SALT, "12345" );
        user.organizationId = "987654321";
        user.organizationName = "test";

        userStorage.store( user );

        assertGet( HTTP_PREFIX() + "/login/?email=test@example.com&password=12345" )
            .isOk()
            .is( response -> response.contentString.get().matches( "id|userEmail|role|expire" ) );
    }

}
