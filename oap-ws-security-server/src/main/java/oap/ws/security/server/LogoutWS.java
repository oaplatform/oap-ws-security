package oap.ws.security.server;

import lombok.extern.slf4j.Slf4j;
import oap.http.HttpResponse;
import oap.ws.WsMethod;
import oap.ws.WsParam;
import oap.ws.security.client.WsSecurity;
import oap.ws.security.api.Role;
import oap.ws.security.api.User;

import java.util.Objects;

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
    public HttpResponse logout( @WsParam( from = QUERY ) String email,
                                @WsParam( from = SESSION ) User user ) {
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
