package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.Producer;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.ClaimValue;

/**
 * A producer for JsonValue injection types
 */
public class JsonValueProducer implements Producer<JsonValue> {
    private MPJWTExtension.ClaimIP claimIP;
    private Type type;
    private Type valueType;

    JsonValueProducer(MPJWTExtension.ClaimIP claimIP) {
        this.claimIP = claimIP;
        HashSet<Type> types = new HashSet<>();
        for(InjectionPoint ip : claimIP.getInjectionPoints()) {
            types.add(ip.getType());
        }
        // Verify that there is only one type this producer is dealing with
        if(types.size() > 1) {
            throw new IllegalStateException(String.format("Multiple injection point types: %s for claim: %s", types, claimIP.getClaim().value()));
        }
        this.type = types.iterator().next();
        this.valueType = type;
        if (type instanceof ParameterizedType) {
            valueType = ((ParameterizedType) type).getActualTypeArguments()[0];
        }
    }
    @Override
    public JsonValue produce(CreationalContext<JsonValue> ctx) {
        System.out.printf("JsonValueProducer(%s).produce\n", claimIP);
        JsonValue jsonValue = MPJWTProducer.generalJsonValueProducer(claimIP.getClaimName());
        return jsonValue;
    }

    @Override
    public void dispose(JsonValue instance) {

    }

    @Override
    public Set<InjectionPoint> getInjectionPoints() {
        return claimIP.getInjectionPoints();
    }

}
