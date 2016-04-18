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

import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import lombok.extern.slf4j.Slf4j;
import oap.http.HttpResponse;
import oap.ws.WsMethod;
import oap.ws.WsParam;
import oap.ws.security.domain.Organization;
import oap.ws.security.domain.Token;
import oap.ws.security.domain.User;
import org.apache.commons.collections4.CollectionUtils;
import org.joda.time.DateTime;

import java.util.List;
import java.util.Optional;

import static java.lang.String.format;
import static oap.http.Request.HttpMethod.DELETE;
import static oap.http.Request.HttpMethod.GET;
import static oap.ws.WsParam.From.PATH;
import static oap.ws.WsParam.From.QUERY;

@Slf4j
public class LoginWS extends OrganizationValidator {

    private final AuthService authService;
    private final String cookieDomain;
    private final DateTime cookieExpiration;

    public LoginWS( OrganizationStorage organizationStorage, AuthService authService,
                    String cookieDomain, int cookieExpiration ) {
        super( organizationStorage );
        this.authService = authService;
        this.cookieDomain = cookieDomain;
        this.cookieExpiration = DateTime.now().plusMinutes( cookieExpiration );
    }

    @WsMethod( method = GET, path = "/" )
    public HttpResponse login( @WsParam( from = QUERY ) String email, @WsParam( from = QUERY ) String password ) {

        final List<Organization.Users> usersList = organizationStorage.select()
            .map( organization -> organization.users )
            .filter( users -> users.get( email ).isPresent() )
            .toList();

        Preconditions.checkState( usersList.size() < 2,
            format( "There are multiple users with the same email [%s]", email ) );

        if( CollectionUtils.isNotEmpty( usersList ) ) {
            final Organization.Users users = Iterables.getOnlyElement( usersList );

            final User user = users.get( email ).get();

            final Optional<Token> optionalToken = authService.generateToken( user, password );

            if( optionalToken.isPresent() ) {
                final Token token = optionalToken.get();
                return HttpResponse.ok( token ).withHeader( "Authorization", token.id )
                    .withCookie( new HttpResponse.CookieBuilder()
                        .withCustomValue( "Authorization", token.id )
                        .withDomain( cookieDomain )
                        .withExpires( cookieExpiration )
                        .build()
                    );
            } else {
                final HttpResponse httpResponse = HttpResponse.status( 500 );
                httpResponse.reasonPhrase = "Cannot generate token for user " + email;

                return httpResponse;
            }
        } else {
            final HttpResponse httpResponse = HttpResponse.status( 500 );
            httpResponse.reasonPhrase = "User " + email + " is unknown";

            return httpResponse;
        }
    }

    @WsMethod( method = DELETE, path = "/{tokenId}" )
    public void logout( @WsParam( from = PATH ) String tokenId ) {
        authService.deleteToken( tokenId );
    }

}
