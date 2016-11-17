/*
 * Copyright (c) Madberry Oy
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */

package oap.ws.security;

import oap.ws.validate.ValidationErrors;

import java.util.Objects;
import java.util.Optional;

import static java.net.HttpURLConnection.HTTP_FORBIDDEN;
import static oap.ws.security.Role.ADMIN;
import static oap.ws.validate.ValidationErrors.empty;
import static oap.ws.validate.ValidationErrors.error;

public interface OrganizationAwareWS {
    @SuppressWarnings( "unused" )
    default ValidationErrors validateOrganizationAccess( User user, String organizationId ) {
        return user.role == ADMIN || Objects.equals( user.organizationId, organizationId )
                ? empty()
                : error( HTTP_FORBIDDEN, "Forbidden" );
    }

    static ValidationErrors validateObjectAccess( Optional<? extends OrganizationAware> object, String organizationId ) {
        return object.map( oa -> !Objects.equals( oa.organization(), organizationId )
                ? error( HTTP_FORBIDDEN, "Forbidden" )
                : empty() )
                .orElse( empty() );
    }
}
