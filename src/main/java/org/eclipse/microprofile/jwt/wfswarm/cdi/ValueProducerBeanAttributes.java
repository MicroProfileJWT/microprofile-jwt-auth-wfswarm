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
 * The BeanAttributes for the ClaimValueProducer and JsonValueProducer
 */
public class ValueProducerBeanAttributes<T> implements BeanAttributes<T> {
    private final Set<Type> myTypes;
    private final Set<Annotation> myQualifiers;
    private final MPJWTExtension.ClaimIP claimIP;

    public ValueProducerBeanAttributes(Set<Type> myTypes, MPJWTExtension.ClaimIP claimIP) {
        this.myTypes = myTypes;
        this.myQualifiers = new HashSet<>();
        this.claimIP = claimIP;
        this.myQualifiers.add(claimIP.getClaim());
        this.myQualifiers.add(new AnnotationLiteral<Any>(){});
    }

    /**
     * Set the producer method bean name to the claim name + the injection site type
     * @return producer method bean name
     */
    @Override
    public String getName() {
        return String.format("%s-%s", claimIP.getClaimName(), claimIP.getMatchType().getTypeName());
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
        return String.format("ClaimValueProducer[%s]", getName());
    }

}