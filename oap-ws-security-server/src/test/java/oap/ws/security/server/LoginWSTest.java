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
import oap.util.Hash;
import oap.ws.security.DefaultUser;
import oap.ws.security.LoginWS;
import oap.ws.security.Role;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static oap.http.testng.HttpAsserts.HTTP_PREFIX;
import static oap.http.testng.HttpAsserts.assertGet;


public class LoginWSTest extends AbstractWsTest {
    public LoginWSTest() {
        super( "ws-login.conf" );
    }

    @BeforeClass
    @Override
    public void beforeClass() {
        super.beforeClass();

        Application.register( "ws-login", new LoginWS( authService, null, 10 ) );

        webServices.start();
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
