/*
 * Copyright (c) Madberry Oy
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */

package oap.ws.security;

import oap.ws.security.OrganizationAware;
import oap.ws.security.User;
import oap.ws.validate.ValidationErrors;

import java.util.Objects;
import java.util.Optional;

import static java.net.HttpURLConnection.HTTP_FORBIDDEN;
import static oap.ws.security.Role.ADMIN;
import static oap.ws.validate.ValidationErrors.empty;
import static oap.ws.validate.ValidationErrors.error;

public interface OrganizationAwareWS {
    @SuppressWarnings( "unused" )
    default ValidationErrors validateOrganizationAccess( User user, String organization ) {
        return user.role == ADMIN || Objects.equals( user.organizationId, organization )
                ? empty()
                : ValidationErrors.error( HTTP_FORBIDDEN, "Forbidden" );
    }

    default ValidationErrors validateObjectAccess( Optional<OrganizationAware> object, String organization ) {
        return object.map( oa -> !Objects.equals( oa.organization(), organization )
                ? ValidationErrors.error( HTTP_FORBIDDEN, "Forbidden" )
                : empty() )
                .orElse( empty() );
    }
}
