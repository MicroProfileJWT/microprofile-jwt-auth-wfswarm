package org.eclipse.microprofile.jwt.wfswarm.cdi;


import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.util.HashSet;
import java.util.Set;

import javax.enterprise.inject.spi.AnnotatedConstructor;
import javax.enterprise.inject.spi.AnnotatedField;
import javax.enterprise.inject.spi.AnnotatedMethod;
import javax.enterprise.inject.spi.AnnotatedType;

import org.eclipse.microprofile.jwt.Claim;

public class DelegateAnnType<T> implements AnnotatedType<ClaimValuesProducer> {
    AnnotatedType<ClaimValuesProducer> delegate;
    HashSet<AnnotatedMethod<? super ClaimValuesProducer>> methods = new HashSet<>();

    DelegateAnnType(Claim claim, AnnotatedType<ClaimValuesProducer> delegate) {
        this.delegate = delegate;
        for(AnnotatedMethod<? super ClaimValuesProducer> m : delegate.getMethods()) {
            DelegateAnnMethod dm = new DelegateAnnMethod<T>(claim, (AnnotatedMethod<ClaimValuesProducer>) m);
            methods.add(dm);
        }
    }

    @Override
    public Class<ClaimValuesProducer> getJavaClass() {
        return delegate.getJavaClass();
    }

    @Override
    public Set<AnnotatedConstructor<ClaimValuesProducer>> getConstructors() {
        return delegate.getConstructors();
    }

    @Override
    public Set<AnnotatedMethod<? super ClaimValuesProducer>> getMethods() {
        return methods;
    }

    @Override
    public Set<AnnotatedField<? super ClaimValuesProducer>> getFields() {
        return delegate.getFields();
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
    public <T extends Annotation> T getAnnotation(Class<T> annotationType) {
        return delegate.getAnnotation(annotationType);
    }

    @Override
    public Set<Annotation> getAnnotations() {
        return delegate.getAnnotations();
    }

    @Override
    public boolean isAnnotationPresent(Class<? extends Annotation> annotationType) {
        return delegate.isAnnotationPresent(annotationType);
    }
}
