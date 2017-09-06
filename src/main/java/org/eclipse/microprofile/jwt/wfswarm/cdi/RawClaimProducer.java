package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.Producer;

import org.eclipse.microprofile.jwt.ClaimValue;

/**
 * This does not work for the non-proxyable types
 *
 * @param <T> claim type
 */
@RequestScoped
public class RawClaimProducer<T> implements Producer<T> {
    RawClaimProducer(MPJWTExtension.ClaimIP claimIP) {
        this.claimIP = claimIP;
        HashSet<Type> types = new HashSet<>();
        for (InjectionPoint ip : claimIP.getInjectionPoints()) {
            types.add(ip.getType());
        }
        // Verify that there is only one type this producer is dealing with
        if (types.size() > 1) {
            throw new IllegalStateException(String.format("Multiple injection point types: %s for claim: %s", types, claimIP.getClaim().value()));
        }
        this.type = types.iterator().next();
        this.valueType = type;
        if (type instanceof ParameterizedType) {
            valueType = ((ParameterizedType) type).getActualTypeArguments()[0];
        }
    }

    @Override
    public T produce(CreationalContext<T> ctx) {
        System.out.printf("RawClaimProducer(%s).produce\n", claimIP);
        ClaimValue<Optional<T>> cv = MPJWTProducer.generalClaimValueProducer(claimIP.getClaimName());
        Optional<T> value = cv.getValue();
        T returnValue = value.orElse(null);
        return returnValue;
    }

    @Override
    public void dispose(Object instance) {

    }

    @Override
    public Set<InjectionPoint> getInjectionPoints() {
        return claimIP.getInjectionPoints();
    }

    private MPJWTExtension.ClaimIP claimIP;

    private Type type;

    private Type valueType;

}
