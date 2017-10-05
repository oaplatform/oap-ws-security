package oap.ws.security.server;

import java.io.Serializable;

/**
 * Created by igor.petrenko on 05.10.2017.
 */
public class Organization implements Serializable {
    private static final long serialVersionUID = 3888224106852999310L;

    public String id;
    public String name;
    public String description;

    public Organization() {
    }

    public Organization( String id ) {
        this.id = id;
    }
}
