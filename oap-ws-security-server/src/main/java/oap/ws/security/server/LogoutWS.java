package oap.ws.security.server;

import lombok.extern.slf4j.Slf4j;
import oap.ws.WsMethod;
import oap.ws.WsParam;
import oap.ws.security.Role;
import oap.ws.security.User;
import oap.ws.security.client.WsSecurity;
import oap.ws.validate.ValidationErrors;
import oap.ws.validate.WsValidate;

import java.util.Objects;

import static java.lang.String.format;
import static java.net.HttpURLConnection.HTTP_FORBIDDEN;
import static oap.http.Request.HttpMethod.DELETE;
import static oap.ws.WsParam.From.QUERY;
import static oap.ws.WsParam.From.SESSION;

@Slf4j
public class LogoutWS {

    private final AuthService authService;

    public LogoutWS( AuthService authService ) {
        this.authService = authService;
    }

    @WsMethod( method = DELETE, path = "/" )
    @WsSecurity( role = Role.USER )
    @WsValidate( { "validateUserAccess" } )
    public void logout( @WsParam( from = QUERY ) String email, @WsParam( from = SESSION ) User user ) {
        log.debug("Invalidating token for user [{}]", email);

        authService.invalidateUser( email );
    }

    @SuppressWarnings("unused")
    public ValidationErrors validateUserAccess(final String email, final User user) {
        return  Objects.equals( user.email, email )
                ? ValidationErrors.empty()
                : ValidationErrors.error( HTTP_FORBIDDEN, format("User [%s] doesn't have enough permissions", user.email) );
    }
}
