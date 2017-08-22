package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.Producer;

import org.eclipse.microprofile.jwt.ClaimValue;

/**
 *
 * @param <T> the raw claim type
 */
public class ClaimValueProducer<T> implements Producer<ClaimValue<T>> {
    private MPJWTExtension.ClaimIP claimIP;
    private Type type;
    private Type valueType;

    ClaimValueProducer(MPJWTExtension.ClaimIP claimIP) {
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
    public ClaimValue<T> produce(CreationalContext<ClaimValue<T>> ctx) {
        System.out.printf("ClaimValueProducer(%s).produce\n", claimIP);
        ClaimValue<Optional<T>> cv = MPJWTProducer.generalClaimValueProducer(claimIP.getClaimName());
        ClaimValue<T> returnValue = (ClaimValue<T>) cv;
        Optional<T> value = cv.getValue();
        if(!valueType.getTypeName().startsWith(Optional.class.getTypeName())) {
            T nestedValue = value.orElse(null);
            ClaimValueWrapper<T> wrapper = new ClaimValueWrapper<>(cv.getName());
            wrapper.setValue(nestedValue);
            returnValue = wrapper;
        }
        return returnValue;
    }

    @Override
    public void dispose(ClaimValue<T> instance) {

    }

    @Override
    public Set<InjectionPoint> getInjectionPoints() {
        return claimIP.getInjectionPoints();
    }

}
