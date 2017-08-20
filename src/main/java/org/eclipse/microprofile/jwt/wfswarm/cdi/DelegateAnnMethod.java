package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.enterprise.inject.spi.AnnotatedMethod;
import javax.enterprise.inject.spi.AnnotatedParameter;
import javax.enterprise.inject.spi.AnnotatedType;

import org.eclipse.microprofile.jwt.Claim;

/**
 * prototype override of AnnotatedMethod to add the correct Claim annotation
 * @param <T>
 */
public class DelegateAnnMethod<T> implements AnnotatedMethod<ClaimValuesProducer> {
    private AnnotatedMethod<ClaimValuesProducer> delegate;
    private HashSet<Annotation> annotations = new HashSet<>();

    public DelegateAnnMethod(Claim claim, AnnotatedMethod<ClaimValuesProducer> delegate) {
        this.delegate = delegate;
        this.annotations.addAll(delegate.getAnnotations());
        this.annotations.add(claim);
    }

    @Override
    public Method getJavaMember() {
        return delegate.getJavaMember();
    }

    @Override
    public List<AnnotatedParameter<ClaimValuesProducer>> getParameters() {
        return delegate.getParameters();
    }

    @Override
    public boolean isStatic() {
        return delegate.isStatic();
    }

    @Override
    public AnnotatedType<ClaimValuesProducer> getDeclaringType() {
        return delegate.getDeclaringType();
    }

    @Override
    public Type getBaseType() {
        return delegate.getBaseType();
    }

    @Override
    public Set<Type> getTypeClosure() {
        return delegate.getTypeClosure();
    }

    @Override
    public <A extends Annotation> A getAnnotation(Class<A> annotationType) {
        A match = null;
        for(Annotation a : annotations) {
            if(a.annotationType().isAssignableFrom(annotationType)) {
                match = (A) a;
                break;
            }
        }
        return match;
    }

    @Override
    public Set<Annotation> getAnnotations() {
        return annotations;
    }

    @Override
    public boolean isAnnotationPresent(Class<? extends Annotation> annotationType) {
        return annotations.contains(annotationType);
    }
}
