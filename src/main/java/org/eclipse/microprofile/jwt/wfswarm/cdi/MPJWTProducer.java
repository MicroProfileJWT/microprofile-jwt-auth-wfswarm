package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.Destroyed;
import javax.enterprise.context.Initialized;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.Producer;
import javax.inject.Provider;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
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

    /**
     * Object the indicated claim value as a JsonValue
     * @param name - name of the claim
     * @return a JsonValue wrapper
     */
    static JsonValue generalJsonValueProducer(String name) {
        Object value = getValue(name, false);
        JsonValue jsonValue = wrapValue(value);
        return jsonValue;
    }

    public static  <T> T getValue(String name, boolean isOptional) {
        JsonWebToken jwt = getJWTPrincpal();
        if (jwt == null) {
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

    static JsonObject replaceMap(Map<String, Object> map) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        for(Map.Entry<String,Object> entry : map.entrySet()) {
            Object entryValue = entry.getValue();
            if(entryValue instanceof Map) {
                JsonObject entryJsonObject = replaceMap((Map<String, Object>) entryValue);
                builder.add(entry.getKey(), entryJsonObject);
            } else if(entryValue instanceof List) {
                JsonArray array = (JsonArray) wrapValue(entryValue);
                builder.add(entry.getKey(), array);
            } else if(entryValue instanceof Long || entryValue instanceof Integer) {
                long lvalue = ((Number) entryValue).longValue();
                builder.add(entry.getKey(), lvalue);
            } else if(entryValue instanceof Double || entryValue instanceof Float) {
                double dvalue = ((Number) entryValue).doubleValue();
                builder.add(entry.getKey(), dvalue);
            } else if(entryValue instanceof Boolean) {
                boolean flag = ((Boolean) entryValue).booleanValue();
                builder.add(entry.getKey(), flag);
            } else if(entryValue instanceof String) {
                builder.add(entry.getKey(), entryValue.toString());
            }
        }
        return builder.build();
    }
    static JsonValue wrapValue(Object value) {
        JsonValue jsonValue = null;
        if(value instanceof JsonValue) {
            // This may already be a JsonValue
            jsonValue = (JsonValue) value;
        }
        else if(value instanceof String) {
            jsonValue = Json.createObjectBuilder()
                    .add("tmp", value.toString())
                    .build()
                    .getJsonString("tmp");
        }
        else if(value instanceof Number) {
            Number number = (Number) value;
            if((number instanceof Long) || (number instanceof Integer)) {
                jsonValue = Json.createObjectBuilder()
                        .add("tmp", number.longValue())
                        .build()
                        .getJsonNumber("tmp");
            } else {
                jsonValue = Json.createObjectBuilder()
                        .add("tmp", number.doubleValue())
                        .build()
                        .getJsonNumber("tmp");
            }
        }
        else if(value instanceof Boolean) {
            Boolean flag = (Boolean) value;
            jsonValue = flag ? JsonValue.TRUE : JsonValue.FALSE;
        }
        else if(value instanceof Collection) {
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            Collection list = (Collection) value;
            for(Object element : list) {
                if(element instanceof String) {
                    arrayBuilder.add(element.toString());
                }
                else {
                    JsonValue jvalue = wrapValue(element);
                    arrayBuilder.add(jvalue);
                }
            }
            jsonValue = arrayBuilder.build();
        }
        else if(value instanceof Map) {
            jsonValue = replaceMap((Map) value);
        }
        return jsonValue;
    }
}
