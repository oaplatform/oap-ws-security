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

import lombok.val;
import oap.ws.security.DefaultUser;
import oap.ws.security.Token;
import oap.ws.security.User;

public final class Converters {

    private Converters() {
    }

    public static DefaultUser toUserDTO( User user ) {
        val userDTO = new DefaultUser();
        userDTO.email = user.getEmail();
        userDTO.role = user.getRole();
        userDTO.organizationId = user.getOrganization();
        if( user instanceof DefaultUser ) {
            val defaultUser = ( DefaultUser ) user;

            userDTO.organizationName = defaultUser.organizationName;
            userDTO.password = defaultUser.password;

        } else {
            userDTO.organizationName = "";
            userDTO.password = "";
        }

        return userDTO;
    }

    public static Token toTokenDTO( Token token ) {
        final Token tokenDTO = new Token();
        tokenDTO.id = token.id;
        tokenDTO.created = token.created;
        tokenDTO.user = toUserDTO( token.user );

        return tokenDTO;
    }

}
