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
import oap.ws.security.domain.Organization;
import oap.ws.security.domain.Role;
import oap.ws.security.domain.User;

import java.util.Optional;

import static oap.http.Request.HttpMethod.*;
import static oap.ws.WsParam.From.*;

@Slf4j
public class OrganizationWS {

    private final OrganizationStorage organizationStorage;
    private final UserStorage userStorage;
    private final String salt;

    public OrganizationWS( OrganizationStorage organizationStorage, UserStorage userStorage, String salt ) {
        this.organizationStorage = organizationStorage;
        this.userStorage = userStorage;
        this.salt = salt;
    }

    @WsMethod( method = POST, path = "/store" )
    @WsSecurity( role = Role.ADMIN )
    public void store( @WsParam( from = BODY ) Organization organization ) {
        log.debug( "Storing organization: [{}]", organization );
        organizationStorage.store( organization );
    }

    @WsMethod( method = GET, path = "/{oid}" )
    @WsSecurity( role = Role.USER )
    public HttpResponse getOrganization( @WsParam( from = PATH ) String oid,
                                         @WsParam( from = SESSION ) User user ) {
        if( user.role.equals( Role.ADMIN ) || user.organizationId.equals( oid ) ) {
            final Optional<Organization> organizationOptional = organizationStorage.get( oid );
            if( organizationOptional.isPresent() ) {
                return HttpResponse.ok( organizationOptional.get() );
            } else {
                final HttpResponse httpResponse = HttpResponse.status( 404 );
                httpResponse.reasonPhrase = "Organization " + oid + " not found";

                log.warn( httpResponse.toString() );

                return httpResponse;
            }
        } else {
            final HttpResponse httpResponse = HttpResponse.status( 403 );
            httpResponse.reasonPhrase = "User " + user.email + " has no access to requested " +
                "organization " + oid;

            log.warn( httpResponse.toString() );

            return httpResponse;
        }
    }

    @WsMethod( method = DELETE, path = "/remove/{oid}" )
    @WsSecurity( role = Role.ADMIN )
    public void removeOrganization( @WsParam( from = PATH ) String oid ) {
        organizationStorage.delete( oid );

        log.debug( "Organization [{}] deleted", oid );
    }

    @WsMethod( method = POST, path = "/{oid}/store-user" )
    @WsSecurity( role = Role.USER )
    public HttpResponse storeUser( @WsParam( from = BODY ) User storeUser, @WsParam( from = PATH ) String oid,
                                   @WsParam( from = SESSION ) User user ) {

        if( !organizationStorage.get( oid ).isPresent() ) {
            final HttpResponse httpResponse = HttpResponse.status( 404 );
            httpResponse.reasonPhrase = "Organization " + oid + " doesn't exists";

            log.warn( httpResponse.toString() );

            return httpResponse;
        }

        if( !storeUser.organizationId.equals( oid ) ) {
            final HttpResponse httpResponse = HttpResponse.status( 409 );
            httpResponse.reasonPhrase = "Cannot save user " + storeUser.email + " with organization " +
                storeUser.organizationId + " to organization " + oid;

            log.warn( httpResponse.toString() );

            return httpResponse;
        }

        final Optional<User> existingUser = userStorage.get( storeUser.email );
        if( existingUser.isPresent() && !existingUser.get().organizationId.equals( oid ) ) {
            final HttpResponse httpResponse = HttpResponse.status( 409 );
            httpResponse.reasonPhrase = "User " + storeUser.email + " is already present in another " +
                "organization";

            log.warn( httpResponse.toString() );

            return httpResponse;
        }

        if( !user.role.equals( Role.ADMIN ) && storeUser.role.precedence < user.role.precedence ) {
            final HttpResponse httpResponse = HttpResponse.status( 403 );
            httpResponse.reasonPhrase = "User with role " + user.role + " can't grant role " +
                storeUser.role + " to user " + storeUser.email;

            log.warn( httpResponse.toString() );

            return httpResponse;
        }

        if( !user.role.equals( Role.ADMIN ) && !user.organizationId.equals( storeUser.organizationId ) ) {
            final HttpResponse httpResponse = HttpResponse.status( 403 );
            httpResponse.reasonPhrase = "User " + user.email + " cannot operate on users from " +
                "different organization " + oid;

            log.warn( httpResponse.toString() );

            return httpResponse;
        }

        if( user.role.equals( Role.USER ) && !user.email.equals( storeUser.email ) ) {
            final HttpResponse httpResponse = HttpResponse.status( 403 );
            httpResponse.reasonPhrase = "User " + user.email + " doesn't have rights to create new users";

            log.warn( httpResponse.toString() );

            return httpResponse;
        }

        storeUser.password = HashUtils.hash( salt, storeUser.password );
        userStorage.store( storeUser );

        log.debug( "New information about user " + storeUser.email + " was successfully added" );

        return HttpResponse.NO_CONTENT;
    }

    @WsMethod( method = GET, path = "/user/{email}" )
    @WsSecurity( role = Role.USER )
    public HttpResponse getUser( @WsParam( from = PATH ) String email,
                                 @WsParam( from = SESSION ) User user ) {
        final Optional<User> userOptional = userStorage.get( email );
        if( userOptional.isPresent() ) {
            final User fetchedUser = userOptional.get();

            if( user.role.equals( Role.ADMIN ) || fetchedUser.organizationId.equals( user.organizationId ) ) {
                final HttpResponse httpResponse = HttpResponse.ok( Converters.toUserDTO( user ) );
                log.debug( httpResponse.toString() );

                return httpResponse;
            } else {
                final HttpResponse httpResponse = HttpResponse.status( 403 );
                httpResponse.reasonPhrase = "User " + user.email + " cannot view users from different organization";

                log.debug( httpResponse.toString() );

                return httpResponse;
            }
        } else {
            final HttpResponse httpResponse = HttpResponse.status( 404 );
            httpResponse.reasonPhrase = "User " + email + " not found";

            log.warn( httpResponse.toString() );

            return httpResponse;
        }

    }

    @WsMethod( method = DELETE, path = "/{oid}/remove-user/{email}" )
    @WsSecurity( role = Role.ORGANIZATION_ADMIN )
    public HttpResponse removeUser( @WsParam( from = PATH ) String oid,
                                    @WsParam( from = PATH ) String email,
                                    @WsParam( from = SESSION ) User user ) {
        if( organizationStorage.get( oid ).isPresent() ) {
            if( user.role.equals( Role.ADMIN ) || user.organizationId.equals( oid ) ) {
                userStorage.delete( email );

                log.debug( "User [{}] deleted", email );

                return HttpResponse.NO_CONTENT;
            } else {

                final HttpResponse httpResponse = HttpResponse.status( 403 );
                httpResponse.reasonPhrase = "User " + email + "cannot perform deletion on " +
                    "foreign organization";

                log.warn( httpResponse.toString() );
                return httpResponse;
            }
        } else {
            final HttpResponse httpResponse = HttpResponse.status( 404 );
            httpResponse.reasonPhrase = "User " + email + "cannot perform deletion on " +
                "foreign organization";

            log.warn( httpResponse.toString() );

            return httpResponse;
        }
    }
}