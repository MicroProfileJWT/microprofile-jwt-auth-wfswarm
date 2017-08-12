package org.eclipse.microprofile.jwt.wfswarm.cdi;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;

import org.eclipse.microprofile.jwt.JsonWebToken;

@ApplicationScoped
public class JWTPrincipalProducer {
    private static ThreadLocal<JsonWebToken> currentPrincipal = new ThreadLocal<>();

    public static void setJWTPrincipal(JsonWebToken principal) {
        currentPrincipal.set(principal);
    }
    public static JsonWebToken getJWTPrincpal() {
        return currentPrincipal.get();
    }

    @PostConstruct
    void init() {
        System.err.println("JWTPrincipalProducer seen");
    }

    @Produces
    @RequestScoped
    JsonWebToken currentPrincipalOrNull() {
        return currentPrincipal.get();
    }
}
