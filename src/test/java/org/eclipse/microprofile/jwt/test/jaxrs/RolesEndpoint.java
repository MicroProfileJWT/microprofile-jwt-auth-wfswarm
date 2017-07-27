package org.eclipse.microprofile.jwt.test.jaxrs;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import java.security.Principal;
import java.util.Date;

@Path("/endp")
public class RolesEndpoint {

    @GET
    @Path("/echo")
    @RolesAllowed("Echoer")
    public String echoInput(@Context SecurityContext sec, @QueryParam("input") String input) {
        Principal user = sec.getUserPrincipal();
        return input + ", user="+user.getName();
    }

    @GET
    @Path("/echo2")
    @RolesAllowed("NoSuchUser")
    public String echoInput2(@Context SecurityContext sec, @QueryParam("input") String input) {
        Principal user = sec.getUserPrincipal();
        String name = user != null ? user.getName() : "<null>";
        return input + ", user="+name;
    }

    @GET
    @Path("/echo3")
    @RolesAllowed("EndpointCustom")
    public String echoInput3(@Context SecurityContext sec, @QueryParam("input") String input) {
        Principal user = sec.getUserPrincipal();
        return input + ", user="+user.getName();
    }

    @GET
    @Path("/heartbeat")
    @PermitAll
    public String heartbeat() {
        return "Heartbeat: "+ new Date(System.currentTimeMillis()).toString();
    }
}
