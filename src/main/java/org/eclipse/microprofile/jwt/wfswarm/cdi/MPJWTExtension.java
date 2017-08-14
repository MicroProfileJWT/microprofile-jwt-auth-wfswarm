package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
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
 * @see org.eclipse.microprofile.jwt.wfswarm.JWTAuthMechanism
 */
public class MPJWTExtension implements Extension {
    public static class ClaimIP implements Comparable<ClaimIP> {
        private Type type;
        private Claim claim;
        private HashSet<InjectionPoint> injectionPoints = new HashSet<>();

        public ClaimIP(Type type, Claim claim) {
            this.type = type;
            this.claim = claim;
        }

        @Override
        public int compareTo(ClaimIP o) {
            return claim.value().compareTo(o.claim.value());
        }

        public Type getType() {
            return type;
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
                    "type=" + type +
                    ", claim=" + claim +
                    ", ips=" + injectionPoints +
                    '}';
        }
    }
    private HashMap<String, ClaimIP> claims = new HashMap<>();

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
            if(claimIP == null) {
                Type type = ip.getType();
                claimIP = new ClaimIP(type, claim);
                claims.put(claim.value(), claimIP);
            }
            claimIP.getInjectionPoints().add(ip);
            System.out.printf("+++ Added Claim(%s) ip: %s\n", claim.value(), ip);
        }
    }
    public void addJWTPrincipalProduer(@Observes BeforeBeanDiscovery bbd, BeanManager beanManager) {
        System.out.printf("MPJWTExtension, added JWTPrincipalProducer\n");
        bbd.addAnnotatedType(beanManager.createAnnotatedType(MPJWTProducer.class));
    }

    public void afterDeploymentValidation(@Observes AfterDeploymentValidation event, BeanManager beanManager) {
        System.err.println("afterDeploymentValidation");
    }

    /**
     * Create producer methods for each ClaimValue injection site
     * @param event -
     * @param beanManager
     */
    void installClaimValueProducerMethods(@Observes final AfterBeanDiscovery event, final BeanManager beanManager) {
        System.out.printf("handleClaimInjections, %s\n", claims);

        // For each @Claim injection point, create a producer method
        for (final ClaimIP claimIP : claims.values()) {
            ProducerFactory<ClaimValueProducer> factory = new ClaimValueProducerFactory(claimIP);
            HashSet<Type> methodTypes = new HashSet<>();
            methodTypes.add(claimIP.type);

            ClaimValueProducerBeanAttributes methodAttributes = new ClaimValueProducerBeanAttributes(methodTypes, claimIP.claim);
            Bean<?> bean = beanManager.createBean(methodAttributes, ClaimValueProducer.class, factory);
            event.addBean(bean);
            System.out.printf("Added %s", bean);
        }
    }
}
