package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.annotation.Annotation;
import java.util.Optional;

import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.InjectionPoint;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;

public class RawClaimTypeProducer {
    @Produces
    @Claim("")
    public Object getValue(InjectionPoint ip) {
        System.out.printf("RawClaimTypeProducer(%s).getValue\n", ip);
        String name = getName(ip);
        ClaimValue<Optional<Object>> cv = MPJWTProducer.generalClaimValueProducer(name);
        Optional<Object> value = cv.getValue();
        Object returnValue = value.orElse(null);
        return returnValue;
    }
    @Produces
    @Claim("")
    public Optional getOptionalValue(InjectionPoint ip) {
        System.out.printf("RawClaimTypeProducer(%s).getOptionalValue\n", ip);
        String name = getName(ip);
        ClaimValue<Optional<Object>> cv = MPJWTProducer.generalClaimValueProducer(name);
        Optional<Object> value = cv.getValue();
        return value;
    }

    String getName(InjectionPoint ip) {
        String name = null;
        for(Annotation ann : ip.getQualifiers()) {
            if(ann instanceof Claim) {
                Claim claim = (Claim) ann;
                name = claim.standard() == Claims.UNKNOWN ? claim.value() : claim.standard().name();
            }
        }
        return name;
    }
}
