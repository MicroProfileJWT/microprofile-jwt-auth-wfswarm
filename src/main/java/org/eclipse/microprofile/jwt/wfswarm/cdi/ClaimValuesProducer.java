package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.util.Optional;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.Annotated;
import javax.enterprise.inject.spi.InjectionPoint;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import static org.eclipse.microprofile.jwt.wfswarm.cdi.MPJWTProducer.getJWTPrincpal;
import static org.eclipse.microprofile.jwt.wfswarm.cdi.MPJWTProducer.getValue;

/**
 * A prototype template class that is used by {@linkplain DelegateAnnMethod}
 */
@RequestScoped
public class ClaimValuesProducer {
    @PostConstruct
    void init() {
        jwt = getJWTPrincpal();
    }

    @Produces
    Object getRawValue(InjectionPoint ip) {
        getClaimValue(ip);
        return value;
    }

    @Produces
    Optional<Object> getOptionalValue(InjectionPoint ip) {
        getClaimValue(ip);
        return Optional.ofNullable(value);
    }

    @Produces
    ClaimValue<Object> getCV(InjectionPoint ip) {
        String name = getClaimValue(ip);
        ClaimValueWrapper<Object> cv = new ClaimValueWrapper<>(name);
        cv.setValue(value);
        return cv;
    }

    @Produces
    ClaimValue<Optional<Object>> getOptionalCV(InjectionPoint ip) {
        String name = getClaimValue(ip);
        ClaimValueWrapper<Optional<Object>> cv = new ClaimValueWrapper<>(name);
        cv.setValue(Optional.of(value));
        return cv;
    }

    private String getClaimValue(InjectionPoint ip) {
        Annotated annotated = ip.getAnnotated();
        Claim claim = annotated.getAnnotation(Claim.class);
        String name = "";
        if (claim != null) {
            if (claim.standard() != Claims.UNKNOWN) {
                name = claim.standard().name();
            } else {
                name = claim.value();
            }
        }
        Optional<Object> optValue = getValue(name, false);
        value = optValue.orElse(null);
        return name;
    }

    JsonWebToken jwt;

    Object value;
}
