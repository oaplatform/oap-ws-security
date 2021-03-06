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

import oap.testng.AbstractTest;
import oap.testng.Env;
import oap.util.Hash;
import oap.ws.security.AuthService;
import oap.ws.security.DefaultUser;
import oap.ws.security.PasswordHasher;
import oap.ws.security.Role;
import oap.ws.security.Token;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

public class AuthServiceTest extends AbstractTest {

    private AuthService authService;
    private UserStorage userStorage;

    @BeforeClass
    public void beforeClass() {
        userStorage = new UserStorage( Env.tmpPath( "users" ) );
        authService = new AuthService( userStorage, new PasswordHasher( "test" ), 1 );
    }

    @AfterClass
    @Override
    public void afterClass() throws Exception {
        userStorage.close();

        super.afterClass();
    }

    @Test
    public void testShouldGenerateNewToken() {
        final DefaultUser user = new DefaultUser();
        user.email = "test@example.com";
        user.password = Hash.sha256( "test", "12345" );
        user.role = Role.ADMIN;

        userStorage.store( user );

        final Token token = authService.generateToken( user.email, "12345" ).get();

        assertEquals( token.user.getRole(), Role.ADMIN );
        assertEquals( token.user.getEmail(), "test@example.com" );
        assertNotNull( token.id );
        assertNotNull( token.created );
    }

    @Test
    public void testShouldDeleteExpiredToken() throws InterruptedException {
        final DefaultUser user = new DefaultUser();
        user.email = "test@example.com";
        user.password = Hash.sha256( "test", "12345" );
        user.role = Role.ADMIN;

        userStorage.store( user );

        authService = new AuthService( userStorage, new PasswordHasher( "test" ), 0 );

        final String id = authService.generateToken( user.email, "12345" ).get().id;
        assertNotNull( id );

        Thread.sleep( 100 );

        assertFalse( authService.getToken( id ).isPresent() );
    }
}
