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
import oap.ws.security.domain.Role;
import oap.ws.security.domain.Token;
import oap.ws.security.domain.User;
import oap.ws.security.server.AuthService;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;

public class AuthServiceTest extends AbstractTest {

    private AuthService authService;

    @BeforeTest
    public void setUp() {
        authService = new AuthService( 1 );
    }

    @Test
    public void testShouldGenerateNewToken() {
        final User user = new User();
        user.email = "test@example.com";
        user.password = "12345";
        user.role = Role.ADMIN;

        final Token token = authService.generateToken( user );

        assertEquals( token.role, Role.ADMIN );
        assertEquals( token.userEmail, "test@example.com" );
        assertNotNull( token.id );
        assertNotNull( token.created );
    }

    @Test
    public void testShouldDeleteExpiredToken() throws InterruptedException {
        final User user = new User();
        user.email = "test@example.com";
        user.password = "12345";
        user.role = Role.ADMIN;

        authService = new AuthService( 0 );

        final String id = authService.generateToken( user ).id;
        assertNotNull( id );

        Thread.sleep( 100 );

        assertFalse( authService.getToken( id ).isPresent() );
    }
}