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
import oap.io.Resources;
import oap.testng.Env;
import oap.ws.SessionManager;
import oap.ws.WebServices;
import oap.ws.WsConfig;
import oap.ws.security.Organization;
import oap.ws.security.Role;
import oap.ws.security.User;
import org.apache.http.entity.ContentType;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.io.IOException;

import static oap.http.testng.HttpAsserts.*;
import static oap.ws.validate.testng.ValidationErrorsAssertion.validating;
import static org.testng.Assert.*;

public class OrganizationWSTest {

   private final Server server = new Server( 100 );
   private final WebServices webServices = new WebServices( server, new SessionManager( 10, null, "/" ),
      new GenericCorsPolicy( "*", "Authorization", true ),
      WsConfig.CONFIGURATION.fromResource( getClass(), "ws-organization.conf" ) );

   private UserStorage userStorage;
   private OrganizationStorage organizationStorage;

   private SynchronizedThread listener;

   private OrganizationWS organizationWS;

   @BeforeClass
   public void startServer() {
      userStorage = new UserStorage( Env.tmpPath( "users" ) );
      organizationStorage = new OrganizationStorage( Env.tmpPath( "organizations" ) );

      organizationWS = new OrganizationWS(organizationStorage, userStorage, "test");

      Application.register( "ws-organization", organizationWS);

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
      final String request = Resources.readString( getClass(), getClass().getSimpleName() + "/12345.json" ).get();

      assertPost( HTTP_PREFIX + "/organization/store", request, ContentType.APPLICATION_JSON )
         .hasCode( 200 );

      final User sessionUser = new User(Role.USER,"12345", "test@test.com");

      final Organization organization = organizationWS.getOrganization( "12345", sessionUser ).get();

      assertEquals( organization.id, "12345" );
      assertEquals( organization.name, "test" );
      assertEquals( organization.description, "test organization" );

      assertDelete( HTTP_PREFIX + "/organization/12345" ).hasCode( 204 );

      assertFalse( organizationStorage.get( "12345" ).isPresent() );
   }

   @Test
   public void testShouldNotStoreUserIfOrganizationDoesNotExist() {
      final User user = new User(Role.USER, "12345", "test@example.com");
      user.password = "123456789";
      user.organizationName = "test";

      final User userUpdate = new User(Role.USER, "98765", "test-2@example.com");

      validating(OrganizationWSI.class)
              .isError(403, "User [test@example.com] has no access to organization [98765]")
              .forInstance(organizationWS)
              .storeUser( userUpdate, "98765", user );
   }

   @Test
   public void testShouldNotStoreUserIfOrganizationMismatch() {
      final User user = new User(Role.ORGANIZATION_ADMIN, "12345","test@example.com");
      user.password = "123456789";
      user.organizationName = "test";

      final Organization organization = new Organization("98765");

      organizationStorage.store( organization );

      final User userUpdate = new User(Role.USER,"98765", "test-2@example.com");

      validating(OrganizationWSI.class)
              .isError(403, "User [test@example.com] has no access to organization [98765]")
              .forInstance(organizationWS)
              .storeUser( userUpdate, "98765", user );
   }

   @Test
   public void testShouldNotStoreUserIfItExistsInAnotherOrganization() {
      final User user = new User(Role.ADMIN, "12345", "test@example.com");
      user.password = "123456789";
      user.organizationName = "test";

      userStorage.store( user );

      final Organization organizationA = new Organization("12345");

      final Organization organizationB = new Organization("98765");

      organizationStorage.store( organizationA );
      organizationStorage.store( organizationB );

      final User userUpdate = new User(Role.USER, "98765", "test@example.com");

      validating(OrganizationWSI.class)
              .isError(409, "User [test@example.com] is already taken")
              .forInstance(organizationWS)
              .storeUser( userUpdate, "98765", user );
   }

   @Test
   public void testShouldSaveUserIfSessionUserIsAdmin() {
      final User user = new User(Role.USER, "12345", "test@example.com");
      user.password = "123456789";
      user.organizationName = "test";

      final Organization organization = new Organization("12345");

      organizationStorage.store( organization );

      final User sessionUser = new User(Role.ADMIN, "someOrg", "98765");

      organizationWS.storeUser( user, "12345", sessionUser );

      assertNotNull( userStorage.get( "test@example.com" ).isPresent() );
   }

   @Test
   public void testShouldNotSaveUserWithHigherRoleThanSessionUserIfNotAdmin() {
      final User user = new User(Role.ADMIN, "12345", "test@example.com");
      user.password = "123456789";
      user.organizationName = "test";

      final Organization organization = new Organization("12345");

      organizationStorage.store( organization );

      final User sessionUser = new User(Role.ORGANIZATION_ADMIN, "12345", "sessionUser@test.com");

      validating(OrganizationWSI.class)
              .isError(403, "User [sessionUser@test.com] doesn't have enough permissions")
              .forInstance(organizationWS)
              .storeUser( user, "12345", sessionUser );
   }

   @Test
   public void testShouldNotSaveUserIfSessionUserHasDifferentOrganization() {
      final User user = new User(Role.USER, "12345", "test@example.com");
      user.password = "123456789";
      user.organizationName = "test";

      final Organization organization = new Organization("12345");

      organizationStorage.store( organization );

      final User sessionUser = new User(Role.ORGANIZATION_ADMIN, "98765", "org-admin@example.com");

      validating(OrganizationWSI.class)
              .isError(403, "User [org-admin@example.com] has no access to organization [12345]")
              .forInstance(organizationWS)
              .storeUser( user, "12345", sessionUser );
   }

   @Test
   public void testShouldSaveUserIfSessionUserIsOrganizationAdmin() {
      final User user = new User(Role.USER, "12345", "test@example.com");
      user.password = "123456789";
      user.organizationName = "test";

      final Organization organization = new Organization("12345");

      organizationStorage.store( organization );

      final User sessionUser = new User(Role.ORGANIZATION_ADMIN, "12345", "sessionUser@example.com");

      organizationWS.storeUser( user, "12345", sessionUser );

      assertNotNull( userStorage.get( "test@example.com" ).isPresent() );
   }
}
