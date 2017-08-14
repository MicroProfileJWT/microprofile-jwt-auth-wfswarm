package org.eclipse.microprofile.jwt.wfswarm.cdi;

import javax.enterprise.inject.Vetoed;

import org.eclipse.microprofile.jwt.ClaimValue;

/**
 * An implementation of the ClaimValue interface
 * @param <T> the claim value type
 */
@Vetoed
public class ClaimValueWrapper<T> implements ClaimValue<T> {
    private String name;
    private T value;

    ClaimValueWrapper(String name) {
        System.err.printf("ClaimValueWrapper[@%s](%s)\n", Integer.toHexString(hashCode()), name);
        this.name = name;
    }
    @Override
    public String getName() {
        return name;
    }

    @Override
    public T getValue() {
        return value;
    }
    void setValue(T value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return String.format("ClaimValueWrapper[@%s], name=%s, value[%s]=%s", Integer.toHexString(hashCode()),
                name, value.getClass(), value);
    }
}
