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
import oap.json.schema.TestJsonValidators;
import oap.testng.Asserts;
import oap.testng.Env;
import oap.util.Lists;
import oap.ws.SessionManager;
import oap.ws.WebServices;
import oap.ws.WsConfig;
import oap.ws.security.DefaultUser;
import oap.ws.security.Role;
import org.apache.http.entity.ContentType;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;

import static oap.http.testng.HttpAsserts.HTTP_PREFIX;
import static oap.http.testng.HttpAsserts.assertDelete;
import static oap.http.testng.HttpAsserts.assertPost;
import static oap.http.testng.HttpAsserts.reset;
import static oap.ws.validate.testng.ValidationErrorsAssertion.validating;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

public class OrganizationWSTest {

    private final Server server = new Server( 100 );
    private final WebServices webServices = new WebServices( server, new SessionManager( 10, null, "/" ),
        new GenericCorsPolicy( "*", "Authorization", true, Lists.of( "POST", "GET" ) ),
        TestJsonValidators.jsonValidatos(),
        WsConfig.CONFIGURATION.fromResource( getClass(), "ws-organization.conf" ) );

    private UserStorage userStorage;
    private OrganizationStorage organizationStorage;

    private SynchronizedThread listener;

    private OrganizationWS organizationWS;

    @BeforeClass
    public void startServer() {
        userStorage = new UserStorage( Env.tmpPath( "users" ) );
        organizationStorage = new OrganizationStorage( Env.tmpPath( "organizations" ) );

        organizationWS = new OrganizationWS( organizationStorage, userStorage, "test" );

        Application.register( "ws-organization", organizationWS );

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
        organizationStorage.clear();
    }

    @Test
    public void testShouldStoreGetDeleteOrganization() throws IOException {
        final String request = Asserts.contentOfTestResource( getClass(), "12345.json" );

        assertPost( HTTP_PREFIX() + "/organization/store", request, ContentType.APPLICATION_JSON )
            .hasCode( 200 );

        final DefaultUser sessionUser = new DefaultUser( Role.USER, "12345", "test@test.com" );

        final Organization organization = organizationWS.organization( "12345", sessionUser ).get();

        assertEquals( organization.id, "12345" );
        assertEquals( organization.name, "test" );
        assertEquals( organization.description, "test organization" );

        assertDelete( HTTP_PREFIX() + "/organization/12345" ).hasCode( 204 );

        assertFalse( organizationStorage.get( "12345" ).isPresent() );
    }

    @Test
    public void testShouldNotStoreUserIfOrganizationDoesNotExist() {
        final DefaultUser user = new DefaultUser( Role.USER, "12345", "test@example.com" );
        user.password = "123456789";
        user.organizationName = "test";

        final DefaultUser userUpdate = new DefaultUser( Role.USER, "98765", "test-2@example.com" );

        validating( OrganizationWSI.class )
            .isError( 403, "Forbidden" )
            .forInstance( organizationWS )
            .userStore( userUpdate, "98765", user );
    }

    @Test
    public void testShouldNotStoreUserIfOrganizationMismatch() {
        final DefaultUser user = new DefaultUser( Role.ORGANIZATION_ADMIN, "12345", "test@example.com" );
        user.password = "123456789";
        user.organizationName = "test";

        final Organization organization = new Organization( "98765" );

        organizationStorage.store( organization );

        final DefaultUser userUpdate = new DefaultUser( Role.USER, "98765", "test-2@example.com" );

        validating( OrganizationWSI.class )
            .isError( 403, "Forbidden" )
            .forInstance( organizationWS )
            .userStore( userUpdate, "98765", user );
    }

    @Test
    public void testShouldNotStoreUserIfItExistsInAnotherOrganization() {
        final DefaultUser user = new DefaultUser( Role.ADMIN, "12345", "test@example.com" );
        user.password = "123456789";
        user.organizationName = "test";

        userStorage.store( user );

        final Organization organizationA = new Organization( "12345" );

        final Organization organizationB = new Organization( "98765" );

        organizationStorage.store( organizationA );
        organizationStorage.store( organizationB );

        final DefaultUser userUpdate = new DefaultUser( Role.USER, "98765", "test@example.com" );

        validating( OrganizationWSI.class )
            .isError( 403, "Forbidden" )
            .forInstance( organizationWS )
            .userStore( userUpdate, "98765", user );
    }

    @Test
    public void testShouldSaveUserIfSessionUserIsAdmin() {
        final DefaultUser user = new DefaultUser( Role.USER, "12345", "test@example.com" );
        user.password = "123456789";
        user.organizationName = "test";

        final Organization organization = new Organization( "12345" );

        organizationStorage.store( organization );

        final DefaultUser sessionUser = new DefaultUser( Role.ADMIN, "someOrg", "98765" );

        organizationWS.userStore( user, "12345", sessionUser );

        assertNotNull( userStorage.get( "test@example.com" ).isPresent() );
    }

    @Test
    public void testShouldNotSaveUserWithHigherRoleThanSessionUserIfNotAdmin() {
        final DefaultUser user = new DefaultUser( Role.ADMIN, "12345", "test@example.com" );
        user.password = "123456789";
        user.organizationName = "test";

        final Organization organization = new Organization( "12345" );

        organizationStorage.store( organization );

        final DefaultUser sessionUser = new DefaultUser( Role.ORGANIZATION_ADMIN, "12345", "sessionUser@test.com" );

        validating( OrganizationWSI.class )
            .isError( 403, "Forbidden" )
            .forInstance( organizationWS )
            .userStore( user, "12345", sessionUser );
    }

    @Test
    public void testShouldNotSaveUserIfSessionUserHasDifferentOrganization() {
        final DefaultUser user = new DefaultUser( Role.USER, "12345", "test@example.com" );
        user.password = "123456789";
        user.organizationName = "test";

        final Organization organization = new Organization( "12345" );

        organizationStorage.store( organization );

        final DefaultUser sessionUser = new DefaultUser( Role.ORGANIZATION_ADMIN, "98765", "org-admin@example.com" );

        validating( OrganizationWSI.class )
            .isError( 403, "Forbidden" )
            .forInstance( organizationWS )
            .userStore( user, "12345", sessionUser );
    }

    @Test
    public void testShouldSaveUserIfSessionUserIsOrganizationAdmin() {
        final DefaultUser user = new DefaultUser( Role.USER, "12345", "test@example.com" );
        user.password = "123456789";
        user.organizationName = "test";

        final Organization organization = new Organization( "12345" );

        organizationStorage.store( organization );

        final DefaultUser sessionUser = new DefaultUser( Role.ORGANIZATION_ADMIN, "12345", "sessionUser@example.com" );

        organizationWS.userStore( user, "12345", sessionUser );

        assertNotNull( userStorage.get( "test@example.com" ).orElse( null ) );
    }
}
