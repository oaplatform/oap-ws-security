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
import oap.util.Hash;
import oap.ws.WsMethod;
import oap.ws.WsParam;
import oap.ws.security.client.WsSecurity;
import oap.ws.security.Converters;
import oap.ws.security.Organization;
import oap.ws.security.Role;
import oap.ws.security.User;
import oap.ws.validate.ValidationErrors;
import oap.ws.validate.WsValidate;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.lang.String.format;
import static java.net.HttpURLConnection.HTTP_CONFLICT;
import static java.net.HttpURLConnection.HTTP_FORBIDDEN;
import static oap.http.Request.HttpMethod.*;
import static oap.ws.WsParam.From.*;
import static oap.ws.security.Role.ADMIN;
import static oap.ws.validate.ValidationErrors.empty;
import static oap.ws.validate.ValidationErrors.error;

@Slf4j
public class OrganizationWS implements OrganizationWSI {

    private final OrganizationStorage organizationStorage;
    private final UserStorage userStorage;
    private final String salt;

    public OrganizationWS(OrganizationStorage organizationStorage, UserStorage userStorage, String salt ) {
        this.organizationStorage = organizationStorage;
        this.userStorage = userStorage;
        this.salt = salt;
    }

    @WsMethod( method = POST, path = "/store" )
    @WsSecurity( role = ADMIN )
    @Override
    public Organization store( @WsParam( from = BODY ) Organization organization ) {
        log.debug( "Storing organization: [{}]", organization );

        organizationStorage.store( organization );

        return organization;
    }

    @WsMethod( method = GET, path = "/all" )
    @WsSecurity( role = ADMIN )
    @Override
    public List<Organization> getAllOrganizations() {
        log.debug( "Fetching all organizations");

        return organizationStorage.select().collect( Collectors.toList() );
    }

    @WsMethod( method = GET, path = "/{organizationId}" )
    @WsSecurity( role = Role.USER )
    @WsValidate({"validateOrganizationAccess"})
    @Override
    public Optional<Organization> getOrganization( @WsParam( from = PATH ) String organizationId,
                                                   @WsParam( from = SESSION ) User user ) {
        return organizationStorage.get( organizationId );
    }

    @WsMethod( method = DELETE, path = "/{organizationId}" )
    @WsSecurity( role = ADMIN )
    @Override
    public void removeOrganization( @WsParam( from = PATH ) String organizationId ) {
        organizationStorage.delete( organizationId );

        log.debug( "Organization [{}] deleted", organizationId );
    }

    @WsMethod( method = GET, path = "/users" )
    @WsSecurity( role = ADMIN )
    @Override
    public List<User> getAllUsers() {
        log.debug( "Fetching all users" );

        return userStorage.select().collect( Collectors.toList() );
    }

    @WsMethod( method = POST, path = "/{organizationId}/store-user" )
    @WsSecurity( role = Role.USER )
    @WsValidate({"validateOrganizationAccess","validateUserUniqueness","validateUserPrecedence","validateUserCreationRole"})
    @Override
    public User storeUser( @WsParam( from = BODY ) User storeUser, @WsParam( from = PATH ) String organizationId,
                           @WsParam( from = SESSION ) User user ) {

        storeUser.password = Hash.sha256( salt, storeUser.password );
        userStorage.store( storeUser );

        log.debug( "New information about user " + storeUser.email + " was successfully added" );

        return Converters.toUserDTO( storeUser );
    }

    @WsMethod( method = GET, path = "/{organizatinoId}/user/{email}" )
    @WsSecurity( role = Role.USER )
    @WsValidate({"validateOrganizationAccess", "validateUserAccessById"})
    @Override
    public Optional<User> getUser( @WsParam(from = PATH) String organizatinoId,
                                   @WsParam( from = PATH ) String email,
                                   @WsParam( from = SESSION ) User user ) {
        return userStorage.get( email );
    }

    @WsMethod( method = DELETE, path = "/{organizationId}/remove-user/{email}" )
    @WsSecurity( role = Role.ORGANIZATION_ADMIN )
    @WsValidate({"validateOrganizationAccess","validateUserAccessById"})
    @Override
    public void removeUser( @WsParam( from = PATH ) String organizationId, @WsParam( from = PATH ) String email,
                            @WsParam( from = SESSION ) User user ) {
        userStorage.delete( email );

        log.debug( "User [{}] deleted", email );
    }

    @SuppressWarnings( "unused" )
    public ValidationErrors validateOrganizationAccess( String organizationId, User user) {
        return user.role == ADMIN || Objects.equals( user.organizationId, organizationId )
                ? ValidationErrors.empty()
                : ValidationErrors.error( HTTP_FORBIDDEN, format( "User [%s] has no access to organization [%s]",
                user.email, organizationId ) );
    }

    @SuppressWarnings( "unused" )
    public ValidationErrors validateUserAccess( String organizationId, User storeUser) {
        return validateUserAccessById(organizationId, storeUser.email);
    }

    @SuppressWarnings( "unused" )
    public ValidationErrors validateUserAccessById( String organizationId, String email) {
        return userStorage.get( email )
                .map( user -> !Objects.equals( user.organizationId, organizationId )
                        ? error( HTTP_FORBIDDEN, format("User [%s] has no access to organization", email ) )
                        : empty() )
                .orElse( empty() );
    }

    @SuppressWarnings( "unused" )
    public ValidationErrors validateUserUniqueness( User storeUser) {
        return userStorage.get(storeUser.email)
                .map(savedUser -> !Objects.equals(storeUser.organizationId, savedUser.organizationId)
                        ? error( HTTP_CONFLICT, format("User [%s] is already taken", storeUser.email ) )
                        : ValidationErrors.empty()
                ).orElse(ValidationErrors.empty());
    }

    @SuppressWarnings( "unused" )
    public ValidationErrors validateUserPrecedence( User user, User storeUser) {
        return ( !user.role.equals( ADMIN ) && storeUser.role.precedence < user.role.precedence )
                ? ValidationErrors.error(HTTP_FORBIDDEN, format("User [%s] doesn't have enough permissions", user.email))
                : ValidationErrors.empty();
    }

    @SuppressWarnings( "unused" )
    public ValidationErrors validateUserCreationRole( User user, User storeUser) {
        return (user.role.equals( Role.USER ) && !user.email.equals( storeUser.email ) )
                ? ValidationErrors.error(HTTP_FORBIDDEN, format("User [%s] doesn't have enough permissions", user.email))
                : ValidationErrors.empty();
    }

}
