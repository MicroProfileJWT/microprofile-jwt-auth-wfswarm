package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Any;
import javax.enterprise.inject.spi.BeanAttributes;
import javax.enterprise.util.AnnotationLiteral;

import org.eclipse.microprofile.jwt.Claim;

/**
 * The BeanAttributes for the ClaimValueProducer
 */
public class ClaimValueProducerBeanAttributes implements BeanAttributes<ClaimValueProducer> {
    private final Set<Type> myTypes;
    private final Set<Annotation> myQualifiers;
    private final Claim claim;

    public ClaimValueProducerBeanAttributes(Set<Type> myTypes, Claim claim) {
        this.myTypes = myTypes;
        this.myQualifiers = new HashSet<>();
        this.claim = claim;
        this.myQualifiers.add(claim);
        this.myQualifiers.add(new AnnotationLiteral<Any>(){});
    }

    @Override
    public String getName() {
        return claim.value();
    }

    @Override
    public Set<Annotation> getQualifiers() {
        return myQualifiers;
    }

    @Override
    public Class<? extends Annotation> getScope() {
        return RequestScoped.class;
    }

    @Override
    public Set<Class<? extends Annotation>>	getStereotypes() {
        return Collections.emptySet();
    }

    @Override
    public Set<Type> getTypes() {
        return myTypes;
    }

    @Override
    public boolean isAlternative() {
        return false;
    }

    @Override
    public String toString() {
        return String.format("ClaimValueProducer[%s]", claim.value());
    }

}