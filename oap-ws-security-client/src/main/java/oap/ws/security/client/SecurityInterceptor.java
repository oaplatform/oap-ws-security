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

import lombok.extern.slf4j.Slf4j;
import oap.http.HttpResponse;
import oap.http.Request;
import oap.http.Session;
import oap.reflect.Reflection;
import oap.ws.Interceptor;
import oap.ws.security.Token;
import oap.ws.security.User;
import oap.ws.security.Role;

import java.util.Optional;

@Slf4j
public class SecurityInterceptor implements Interceptor {

    private final TokenService tokenService;

    public SecurityInterceptor( TokenService tokenService ) {
        this.tokenService = tokenService;
    }

    @Override
    public Optional<HttpResponse> intercept( Request request, Session session, Reflection.Method method ) {
        final Optional<WsSecurity> annotation = method.findAnnotation( WsSecurity.class );
        if( annotation.isPresent() ) {
            if( session == null ) {
                log.error( "Session doesn't exist; check if service is session aware" );
                final HttpResponse response = HttpResponse.status( 500 );
                response.reasonPhrase = "Session doesn't exist; check if service is session aware";

                return Optional.of( response );
            }

            final Optional<Object> optionalUser = session.get( "user" );
            if( optionalUser.isPresent() ) {
                final User user = ( User ) optionalUser.get();
                log.trace( "User [{}] found in session", user.email );

                final Role methodRole = annotation.get().role();

                if( user.role.precedence > methodRole.precedence ) {
                    log.debug( "User [{}] has no access to method [{}]", user.email, method.name() );
                    return Optional.of( HttpResponse.status( 403 ) );
                }
            } else {
                final String sessionToken = request.header( "Authorization" ).isPresent() ?
                    request.header( "Authorization" ).get() : request.cookies().get( "Authorization" );

                if( sessionToken == null ) {
                    log.debug( "Session or authorization token is missing in header or cookie",
                        request.context.location );
                    final HttpResponse response = HttpResponse.status( 401 );
                    response.reasonPhrase = "Session token is missing in header or cookie";

                    return Optional.of( response );
                }

                final Optional<Token> optionalToken = tokenService.getToken( sessionToken );

                if( !optionalToken.isPresent() ) {
                    log.debug( "Token id [{}] expired or was not created", sessionToken );
                    final HttpResponse response = HttpResponse.status( 401 );
                    response.reasonPhrase = "Auth token for user expired or was not created";

                    return Optional.of( response );
                }

                final Token token = optionalToken.get();
                final User user = token.user;

                session.set( "sessionToken", token.id );
                session.set( "user", user );

                final Role methodRole = annotation.get().role();

                if( user.role.precedence > methodRole.precedence ) {
                    log.debug( "User [{}] has no access to method [{}]", user.email, method.name() );
                    return Optional.of( HttpResponse.status( 403 ) );
                }
            }
        }

        return Optional.empty();
    }
}
