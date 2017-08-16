package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Destroyed;
import javax.enterprise.context.Initialized;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Produces;

import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * A class that tracks the current validated MP-JWT and associated JsonWebToken via a thread
 * local to provide a @RequestScoped JsonWebToken producer method.
 *
 * It also provides utility methods for access the current JsonWebToken claim values.
 */
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

    /**
     * The @RequestScoped producer method for the current JsonWebToken
     * @return
     */
    @Produces
    @RequestScoped
    JsonWebToken currentPrincipalOrNull() {
        return currentPrincipal.get();
    }

    /**
     * A utility method for accessing a claim from the current JsonWebToken as a ClaimValue<Optional<T>> object.
     * @param name - name of the claim
     * @param <T> expected actual type of the claim
     * @return the claim value wrapper object
     */
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
}
