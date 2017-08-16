package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.AfterDeploymentValidation;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.ProcessInjectionPoint;
import javax.enterprise.inject.spi.ProcessProducer;
import javax.enterprise.inject.spi.ProducerFactory;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.JsonWebToken;

/**
 * A CDI extension that provides a producer for the current authenticated JsonWebToken based on a thread
 * local value that is managed by the {@link org.eclipse.microprofile.jwt.wfswarm.JWTAuthMechanism} request
 * authentication handler.
 *
 * This also installs the producer methods for the discovered @Claim ClaimValue<T> injection sites.
 *
 * @see org.eclipse.microprofile.jwt.wfswarm.JWTAuthMechanism
 */
public class MPJWTExtension implements Extension {
    public static class ClaimIPType implements Comparable<ClaimIPType> {
        private String claimName;
        private Type ipType;

        public ClaimIPType(String claimName, Type ipType) {
            this.claimName = claimName;
            this.ipType = ipType;
        }

        /**
         * Order the @Claim ClaimValue<T> on the @Claim.value and then T type name
         * @param o - ClaimIP to compare to
         * @return the ordering of this claim relative to o
         */
        @Override
        public int compareTo(ClaimIPType o) {
            int compareTo = claimName.compareTo(o.claimName);
            if(compareTo == 0) {
                compareTo = ipType.getTypeName().compareTo(o.ipType.getTypeName());
            }
            return compareTo;
        }
    }
    public static class ClaimIP {
        /** The injection site value type */
        private Type matchType;
        /** The actual type of of the ParameterizedType matchType */
        private Type valueType;
        /** Is valueType actually wrapped in an Optional */
        private boolean isOptional;
        /** The injection site @Claim annotation value */
        private Claim claim;
        /** The location that share the @Claim/type combination */
        private HashSet<InjectionPoint> injectionPoints = new HashSet<>();

        /**
         *
         * @param matchType
         * @param valueType
         * @param isOptional
         * @param claim
         */
        public ClaimIP(Type matchType, Type valueType, boolean isOptional, Claim claim) {
            this.matchType = matchType;
            this.valueType = valueType;
            this.claim = claim;
        }

        public Type getMatchType() {
            return matchType;
        }

        public Claim getClaim() {
            return claim;
        }
        public Set<InjectionPoint> getInjectionPoints() {
            return injectionPoints;
        }

        @Override
        public String toString() {
            return "ClaimIP{" +
                    "type=" + matchType +
                    ", claim=" + claim +
                    ", ips=" + injectionPoints +
                    '}';
        }
    }
    private HashMap<ClaimIPType, ClaimIP> claims = new HashMap<>();

    /**
     * Register the MPJWTProducer JsonWebToken producer bean
     * @param bbd before discovery event
     * @param beanManager cdi bean manager
     */
    public void addJWTPrincipalProduer(@Observes BeforeBeanDiscovery bbd, BeanManager beanManager) {
        System.out.printf("MPJWTExtension, added JWTPrincipalProducer\n");
        bbd.addAnnotatedType(beanManager.createAnnotatedType(MPJWTProducer.class));
    }

    void doProcessProducers(@Observes ProcessProducer pp) {
        System.out.printf("pp: %s, %s\n", pp.getAnnotatedMember(), pp.getProducer());
    }
    void processJWTPrincipalInjections(@Observes ProcessInjectionPoint pip) {
        System.out.printf("pip: %s\n", pip.getInjectionPoint());
        InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getType().getTypeName().equals(JsonWebToken.class.getTypeName())) {
            System.out.printf("+++ JsonWebToken target: %s\n", ip);
        }
    }
    /**
     * Collect the types of all injection points annotated with {@linkplain Claim}.
     * @param pip - the injection point event information
     */
    void processInjection(@Observes ProcessInjectionPoint<?, ClaimValue> pip) {
        System.out.printf("processInjection: %s\n", pip.getInjectionPoint());
        InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getAnnotated().isAnnotationPresent(Claim.class)) {
            Claim claim = ip.getAnnotated().getAnnotation(Claim.class);
            System.out.printf("Checking Claim(%s), ip: %s\n", claim.value(), ip);
            ClaimIP claimIP = claims.get(claim.value());
            ClaimIPType key = new ClaimIPType(claim.value(), ip.getType());
            if(claimIP == null) {
                // Pull out the ClaimValue<T> T type,
                Type matchType = ip.getType();
                Type actualType = Object.class;
                boolean isOptional = false;
                if(matchType instanceof ParameterizedType) {
                    actualType = ((ParameterizedType) matchType).getActualTypeArguments()[0];
                    isOptional = matchType.getTypeName().equals(Optional.class.getTypeName());
                    if (isOptional) {
                        actualType = ((ParameterizedType) matchType).getActualTypeArguments()[0];
                    }
                }

                claimIP = new ClaimIP(matchType, actualType, isOptional, claim);
                claims.put(key, claimIP);
            }
            claimIP.getInjectionPoints().add(ip);
            System.out.printf("+++ Added Claim(%s) ip: %s\n", claim.value(), ip);
        }
    }

    public void afterDeploymentValidation(@Observes AfterDeploymentValidation event, BeanManager beanManager) {
        System.err.println("afterDeploymentValidation");
    }

    /**
     * Create producer methods for each ClaimValue injection site
     * @param event - after bean discovery event
     * @param beanManager - cdi bean manager
     */
    void installClaimValueProducerMethods(@Observes final AfterBeanDiscovery event, final BeanManager beanManager) {
        System.out.printf("handleClaimInjections, %s\n", claims);

        // For each @Claim injection point type, add a producer method
        for (final ClaimIP claimIP : claims.values()) {
            // Pass in the ClaimIP so the producer knows the actual type
            ProducerFactory<ClaimValueProducer> factory = new ClaimValueProducerFactory(claimIP);
            // Use the ClaimIP#matchType as the type against the producer method will be matched
            HashSet<Type> methodTypes = new HashSet<>();
            methodTypes.add(claimIP.matchType);
            // Create the BeanAttributes for the injection site producer method
            ClaimValueProducerBeanAttributes methodAttributes = new ClaimValueProducerBeanAttributes(methodTypes, claimIP);
            // Create the producer method bean with the custom producer factory
            Bean<?> bean = beanManager.createBean(methodAttributes, ClaimValueProducer.class, factory);
            event.addBean(bean);
            System.out.printf("Added %s", bean);
        }
    }
}
