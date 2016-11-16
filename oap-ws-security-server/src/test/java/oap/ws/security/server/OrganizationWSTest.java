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

   @BeforeClass
   public void startServer() {
      userStorage = new UserStorage( Env.tmpPath( "users" ) );
      organizationStorage = new OrganizationStorage( Env.tmpPath( "organizations" ) );

      Application.register( "ws-organization", new OrganizationWS( organizationStorage, userStorage, "test" ) );

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
      final OrganizationWS organizationWSImpl = new OrganizationWS( organizationStorage, userStorage, "test" );

      final User sessionUser = new User();
      sessionUser.organizationId = "12345";
      sessionUser.role = Role.USER;

      final Organization organization = organizationWSImpl.getOrganization( "12345", sessionUser ).get();

      assertEquals( organization.id, "12345" );
      assertEquals( organization.name, "test" );
      assertEquals( organization.description, "test organization" );

      assertDelete( HTTP_PREFIX + "/organization/12345" ).hasCode( 204 );

      assertFalse( organizationStorage.get( "12345" ).isPresent() );
   }

   @Test
   public void testShouldNotStoreUserIfOrganizationDoesNotExist() {
      final OrganizationWS organizationWSImpl = new OrganizationWS( organizationStorage, userStorage, "test" );
      final User user = new User();
      user.email = "test@example.com";
      user.password = "123456789";
      user.role = Role.USER;
      user.organizationId = "12345";
      user.organizationName = "test";

      final User userUpdate = new User();
      userUpdate.email = "test-2@example.com";
      userUpdate.organizationId = "98765";
      userUpdate.role = Role.USER;

      validating(OrganizationWSI.class)
              .isError(403, "User [test@example.com] has no access to organization [98765]")
              .forInstance(organizationWSImpl)
              .storeUser( userUpdate, "98765", user );
   }

   @Test
   public void testShouldNotStoreUserIfOrganizationMismatch() {
      final OrganizationWS organizationWSImpl = new OrganizationWS( organizationStorage, userStorage, "test" );
      final User user = new User();
      user.email = "test@example.com";
      user.password = "123456789";
      user.role = Role.ORGANIZATION_ADMIN;
      user.organizationId = "12345";
      user.organizationName = "test";

      final Organization organization = new Organization();
      organization.id = "98765";

      organizationStorage.store( organization );

      final User userUpdate = new User();
      userUpdate.email = "test-2@example.com";
      userUpdate.organizationId = "98765";
      userUpdate.role = Role.USER;

      validating(OrganizationWSI.class)
              .isError(403, "User [test@example.com] has no access to organization [98765]")
              .forInstance(organizationWSImpl)
              .storeUser( userUpdate, "98765", user );
   }

   @Test
   public void testShouldNotStoreUserIfItExistsInAnotherOrganization() {
      final OrganizationWS organizationWSImpl = new OrganizationWS( organizationStorage, userStorage, "test" );
      final User user = new User();
      user.email = "test@example.com";
      user.password = "123456789";
      user.role = Role.ADMIN;
      user.organizationId = "12345";
      user.organizationName = "test";

      userStorage.store( user );

      final Organization organizationA = new Organization();
      organizationA.id = "12345";

      final Organization organizationB = new Organization();
      organizationB.id = "98765";

      organizationStorage.store( organizationA );
      organizationStorage.store( organizationB );

      final User userUpdate = new User();
      userUpdate.email = "test@example.com";
      userUpdate.organizationId = "98765";
      userUpdate.role = Role.USER;

      validating(OrganizationWSI.class)
              .isError(409, "User [test@example.com] is already taken")
              .forInstance(organizationWSImpl)
              .storeUser( userUpdate, "98765", user );
   }

   @Test
   public void testShouldSaveUserIfSessionUserIsAdmin() {
      final OrganizationWS organizationWSImpl = new OrganizationWS( organizationStorage, userStorage, "test" );
      final User user = new User();
      user.email = "test@example.com";
      user.password = "123456789";
      user.role = Role.USER;
      user.organizationId = "12345";
      user.organizationName = "test";

      final Organization organization = new Organization();
      organization.id = "12345";
      organizationStorage.store( organization );

      final User sessionUser = new User();
      sessionUser.role = Role.ADMIN;

      organizationWSImpl.storeUser( user, "12345", sessionUser );

      assertNotNull( userStorage.get( "test@example.com" ).isPresent() );
   }

   @Test
   public void testShouldNotSaveUserWithHigherRoleThanSessionUserIfNotAdmin() {
      final OrganizationWS organizationWSImpl = new OrganizationWS( organizationStorage, userStorage, "test" );
      final User user = new User();
      user.email = "test@example.com";
      user.password = "123456789";
      user.role = Role.ADMIN;
      user.organizationId = "12345";
      user.organizationName = "test";

      final Organization organization = new Organization();
      organization.id = "12345";
      organizationStorage.store( organization );

      final User sessionUser = new User();
      sessionUser.email = "sessionUser@user.com";
      sessionUser.role = Role.ORGANIZATION_ADMIN;
      sessionUser.organizationId = "12345";

      validating(OrganizationWSI.class)
              .isError(403, "User [sessionUser@user.com] doesn't have enough permissions")
              .forInstance(organizationWSImpl)
              .storeUser( user, "12345", sessionUser );
   }

   @Test
   public void testShouldNotSaveUserIfSessionUserHasDifferentOrganization() {
      final OrganizationWS organizationWSImpl = new OrganizationWS( organizationStorage, userStorage, "test" );
      final User user = new User();
      user.email = "test@example.com";
      user.password = "123456789";
      user.role = Role.USER;
      user.organizationId = "12345";
      user.organizationName = "test";

      final Organization organization = new Organization();
      organization.id = "12345";
      organizationStorage.store( organization );

      final User sessionUser = new User();
      sessionUser.email = "org-admin@example.com";
      sessionUser.organizationId = "98765";
      sessionUser.role = Role.ORGANIZATION_ADMIN;

      validating(OrganizationWSI.class)
              .isError(403, "User [org-admin@example.com] has no access to organization [12345]")
              .forInstance(organizationWSImpl)
              .storeUser( user, "12345", sessionUser );
   }

   @Test
   public void testShouldSaveUserIfSessionUserIsOrganizationAdmin() {
      final OrganizationWS organizationWSImpl = new OrganizationWS( organizationStorage, userStorage, "test" );
      final User user = new User();
      user.email = "test@example.com";
      user.password = "123456789";
      user.role = Role.USER;
      user.organizationId = "12345";
      user.organizationName = "test";

      final Organization organization = new Organization();
      organization.id = "12345";
      organizationStorage.store( organization );

      final User sessionUser = new User();
      sessionUser.organizationId = "12345";
      sessionUser.role = Role.ORGANIZATION_ADMIN;

      organizationWSImpl.storeUser( user, "12345", sessionUser );

      assertNotNull( userStorage.get( "test@example.com" ).isPresent() );
   }
}
