package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.annotation.Annotation;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.Destroyed;
import javax.enterprise.context.Initialized;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.context.spi.Context;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.InjectionPoint;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.JsonWebToken;

@ApplicationScoped
public class MPJWTProducer {
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
    void observeRequestInitialized(@Observes @Initialized(RequestScoped.class) Object event) {
        System.err.printf("observeRequestInitialized, event=%s\n", event);
    }
    void observeRequestDestroyed(@Observes @Destroyed(RequestScoped.class) Object event) {
        System.err.printf("observeRequestDestroyed, event=%s\n", event);
    }

    @Produces
    @RequestScoped
    JsonWebToken currentPrincipalOrNull() {
        return currentPrincipal.get();
    }

    @RequestScoped
    static <T> ClaimValue<Optional<T>> generalClaimValueProducer(String name) {
        ClaimValueWrapper<Optional<T>> wrapper = new ClaimValueWrapper<>(name);
        T value = getValue(name, false);
        Optional<T> optValue = Optional.ofNullable(value);
        wrapper.setValue(optValue);
        return wrapper;
    }

    static  <T> T getValue(String name, boolean isOptional) {
        JsonWebToken jwt = getJWTPrincpal();
        if (name == null || name.isEmpty() || jwt == null) {
            System.out.printf("getValue(%s), null JsonWebToken\n", name);
            return null;
        }

        Optional<T> claimValue = jwt.claim(name);
        if(!isOptional && !claimValue.isPresent()) {
            System.err.printf("Failed to find Claim for: %s\n", name);
        }
        System.out.printf("getValue(%s), isOptional=%s, claimValue=%s\n", name, isOptional, claimValue);
        return claimValue.orElse(null);
    }

    private String getName(InjectionPoint injectionPoint) {
        for (Annotation qualifier : injectionPoint.getQualifiers()) {
            if (qualifier.annotationType().equals(Claim.class)) {
                // Check for a non-default value
                String name = ((Claim) qualifier).value();
                return name;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private <T> Class<T> unwrapType(Type type) {
        if (type instanceof ParameterizedType) {
            type = ((ParameterizedType) type).getActualTypeArguments()[0];
        }
        return (Class<T>) type;
    }
}
