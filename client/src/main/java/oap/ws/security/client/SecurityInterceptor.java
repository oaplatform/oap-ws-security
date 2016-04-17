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

package oap.ws.security.client;

import oap.http.HttpResponse;
import oap.http.Request;
import oap.http.Session;
import oap.reflect.Reflection;
import oap.ws.Interceptor;
import oap.ws.security.domain.Role;
import oap.ws.security.domain.Token;
import oap.ws.security.domain.User;

import java.net.HttpCookie;
import java.util.List;
import java.util.Optional;

public class SecurityInterceptor implements Interceptor {

    private final TokenService tokenService;

    public SecurityInterceptor( TokenService tokenService ) {
        this.tokenService = tokenService;
    }

    private static String getTokenFromCookie( List<HttpCookie> cookies ) {
        for( HttpCookie httpCookie : cookies ) {
            if( httpCookie.getName().equals( "Authorization" ) ) {
                return httpCookie.getValue();
            }
        }

        return null;
    }

    @Override
    public Optional<HttpResponse> intercept( Request request, Session session, Reflection.Method method ) {
        final Optional<WsSecurity> annotation = method.findAnnotation( WsSecurity.class );
        if( annotation.isPresent() ) {
            final Optional<Object> optionalUser = session.get( "user" );
            if( optionalUser.isPresent() ) {
                final User user = ( User ) optionalUser.get();
                final Role methodRole = annotation.get().role();

                if( user.role.precedence > methodRole.precedence ) {
                    return Optional.of( HttpResponse.status( 403 ) );
                }
            } else {
                final String sessionToken = request.header( "Authorization" ).isPresent() ?
                    request.header( "Authorization" ).get() : getTokenFromCookie( request.cookies() );

                if( sessionToken == null ) {
                    return Optional.of( HttpResponse.status( 401 ) );
                }

                final Optional<Token> optionalToken = tokenService.getToken( sessionToken );

                if( !optionalToken.isPresent() ) {
                    return Optional.of( HttpResponse.status( 401 ) );
                }

                final Token token = optionalToken.get();
                final User user = token.user;

                session.set( "sessionToken", token.id );
                session.set( "user", user );

                final Role methodRole = annotation.get().role();

                if( user.role.precedence > methodRole.precedence ) {
                    return Optional.of( HttpResponse.status( 403 ) );
                }
            }
        }

        return Optional.empty();
    }
}
