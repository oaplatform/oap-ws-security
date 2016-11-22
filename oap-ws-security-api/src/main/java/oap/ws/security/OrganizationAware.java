/*
 * Copyright (c) Madberry Oy
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */

package oap.ws.security;

import java.util.Objects;

public interface OrganizationAware {
    String organization();

    default boolean belongsToOrganization( String organizationId ) {
        return Objects.equals( organization(), organizationId );
    }
}
