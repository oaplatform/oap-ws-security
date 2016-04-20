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
import oap.ws.WsMethod;
import oap.ws.WsParam;
import oap.ws.security.client.WsSecurity;
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
        organizationStorage.store( organization );
    }

    @WsMethod( method = GET, path = "/{oid}" )
    @WsSecurity( role = Role.USER )
    public Optional<Organization> getOrganization( @WsParam( from = PATH ) String oid ) {
        return organizationStorage.get( oid );
    }

    @WsMethod( method = DELETE, path = "/remove/{oid}" )
    @WsSecurity( role = Role.ADMIN )
    public void removeOrganization( @WsParam( from = PATH ) String oid ) {
        organizationStorage.delete( oid );
    }

    @WsMethod( method = POST, path = "/{oid}/store-user" )
    @WsSecurity( role = Role.USER )
    public void storeUser( @WsParam( from = BODY ) User user, @WsParam( from = PATH ) String oid,
                           @WsParam( from = SESSION ) User userSession ) {

        if( organizationStorage.get( oid ).isPresent() ) {
            if( user.organizationId.equals( oid ) ) {
                final Optional<User> userOptional = userStorage.get( user.email );
                if( userOptional.isPresent() && !userOptional.get().organizationId.equals( oid ) ) {
                    log.warn( "User " + user.email + " is already present in another " +
                        "organization" );
                    throw new IllegalStateException( "User " + user.email + " is already present in another " +
                        "organization" );
                }

                if( userSession.role.equals( Role.ADMIN ) ) {
                    user.password = HashUtils.hash( salt, user.password );
                    userStorage.store( user );
                } else {
                    if( user.role.precedence < userSession.role.precedence ) {
                        log.warn( "User with role " + userSession.role + " can't grant role " +
                            user.role + " to user " + user.email );
                        throw new IllegalStateException( "User with role " + userSession.role + " can't grant role " +
                            user.role + " to user " + user.email );
                    }

                    if( !userSession.organizationId.equals( user.organizationId ) ) {
                        log.warn( "User " + userSession.email + " cannot operate on users from " +
                            "different organization " + oid );
                        throw new IllegalStateException( "User " + userSession.email + " cannot operate on users from " +
                            "different organization " + oid );
                    }

                    user.password = HashUtils.hash( salt, user.password );
                    userStorage.store( user );
                }
            } else {
                log.warn( "Cannot save user " + user.email + " with organization " +
                    user.organizationId + " to organization " + oid );
                throw new IllegalStateException( "Cannot save user " + user.email + " with organization " +
                    user.organizationId + " to organization " + oid );
            }
        } else {
            log.warn( "Organization " + oid + " doesn't exists" );
            throw new IllegalStateException( "Organization " + oid + " doesn't exists" );
        }
    }

    @WsMethod( method = GET, path = "/{oid}/user/{email}" )
    @WsSecurity( role = Role.ORGANIZATION_ADMIN )
    public Optional<User> getUser( @WsParam( from = PATH ) String oid,
                                   @WsParam( from = PATH ) String email ) {
        if( organizationStorage.get( oid ).isPresent() ) {
            final Optional<User> userOptional = userStorage.get( email );
            if( userOptional.isPresent() ) {
                final User user = userOptional.get();

                return user.organizationId.equals( oid ) ? Optional.of( user ) : Optional.empty();
            } else {
                log.debug( "User " + email + " doesn't exist" );
                return Optional.empty();
            }
        } else {
            log.warn( "Organization " + oid + "doesn't exist" );
            throw new IllegalStateException( "Organization " + oid + "doesn't exist" );
        }
    }

    @WsMethod( method = DELETE, path = "/{oid}/remove-user/{email}" )
    @WsSecurity( role = Role.ORGANIZATION_ADMIN )
    public void removeUser( @WsParam( from = PATH ) String oid,
                            @WsParam( from = PATH ) String email ) {
        if( organizationStorage.get( oid ).isPresent() ) {
            userStorage.delete( email );
        } else {
            log.warn( "Organization " + oid + "doesn't exist" );
            throw new IllegalStateException( "Organization " + oid + "doesn't exist" );
        }
    }
}