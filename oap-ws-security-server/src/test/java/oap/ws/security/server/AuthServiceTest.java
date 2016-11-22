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
import oap.ws.security.Role;
import oap.ws.security.Token;
import oap.ws.security.User;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

public class AuthServiceTest extends AbstractTest {

    private AuthService authService;
    private UserStorage userStorage;

    @BeforeTest
    public void setUp() {
        userStorage = new UserStorage( Env.tmpPath( "users" ) );
        authService = new AuthService( userStorage, 1, "test" );
    }

    @AfterTest
    public void tearDown() {
        userStorage.clear();
    }

    @Test
    public void testShouldGenerateNewToken() {
        final User user = new User();
        user.email = "test@example.com";
        user.password = Hash.sha256( "test", "12345" );
        user.role = Role.ADMIN;

        userStorage.store( user );

        final Token token = authService.generateToken( user.email, "12345" ).get();

        assertEquals( token.user.role, Role.ADMIN );
        assertEquals( token.user.email, "test@example.com" );
        assertNotNull( token.id );
        assertNotNull( token.created );
    }

    @Test
    public void testShouldDeleteExpiredToken() throws InterruptedException {
        final User user = new User();
        user.email = "test@example.com";
        user.password = Hash.sha256( "test", "12345" );
        user.role = Role.ADMIN;

        userStorage.store( user );

        authService = new AuthService( userStorage, 0, "test" );

        final String id = authService.generateToken( user.email, "12345" ).get().id;
        assertNotNull( id );

        Thread.sleep( 100 );

        assertFalse( authService.getToken( id ).isPresent() );
    }
}
