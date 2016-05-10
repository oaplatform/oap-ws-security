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

import lombok.extern.slf4j.Slf4j;
import oap.http.HttpResponse;
import oap.ws.WsMethod;
import oap.ws.WsParam;
import oap.ws.security.client.WsSecurity;
import oap.ws.security.domain.Converters;
import oap.ws.security.domain.Role;
import oap.ws.security.domain.Token;
import oap.ws.security.domain.User;
import org.joda.time.DateTime;

import java.util.Objects;
import java.util.Optional;

import static oap.http.Request.HttpMethod.DELETE;
import static oap.http.Request.HttpMethod.GET;
import static oap.ws.WsParam.From.PATH;
import static oap.ws.WsParam.From.QUERY;

@Slf4j
public class LoginWS {

    private final AuthService authService;
    private final String cookieDomain;
    private final DateTime cookieExpiration;

    public LoginWS( AuthService authService, String cookieDomain, int cookieExpiration ) {
        this.authService = authService;
        this.cookieDomain = cookieDomain;
        this.cookieExpiration = DateTime.now().plusMinutes( cookieExpiration );
    }

    @WsMethod( method = GET, path = "/" )
    public HttpResponse login( @WsParam( from = QUERY ) String email, @WsParam( from = QUERY ) String password ) {
        final Optional<Token> optionalToken = authService.generateToken( email, password );

        if( optionalToken.isPresent() ) {
            final Token token = optionalToken.get();
            return HttpResponse.ok( Converters.toTokenDTO( token ) ).withHeader( "Authorization", token.id )
                .withCookie( new HttpResponse.CookieBuilder()
                    .withCustomValue( "Authorization", token.id )
                    .withDomain( cookieDomain )
                    .withExpires( cookieExpiration )
                    .build()
                );
        } else {
            final HttpResponse httpResponse = HttpResponse.status( 400 );
            httpResponse.reasonPhrase = "Username or password is invalid";

            log.debug( httpResponse.reasonPhrase );

            return httpResponse;
        }

    }

    @WsMethod( method = DELETE, path = "/{email}" )
    @WsSecurity( role = Role.USER )
    public HttpResponse logout( @WsParam( from = PATH ) String email,
                                @WsParam( from = PATH ) User user ) {
        if( !Objects.equals( user.email, email ) ) {
            final HttpResponse httpResponse = HttpResponse.status( 403, "User " + user.email + " cannot logout " +
                "another users" );

            log.debug( httpResponse.reasonPhrase );

            return httpResponse;
        }

        authService.invalidateUser( email );

        return HttpResponse.status( 204, "User " + email + " was successfully logged out" );
    }

}
