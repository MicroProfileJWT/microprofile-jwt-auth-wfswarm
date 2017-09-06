package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.annotation.Annotation;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.SessionScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.AfterDeploymentValidation;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.inject.spi.BeanAttributes;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.ProcessBeanAttributes;
import javax.enterprise.inject.spi.ProcessInjectionPoint;
import javax.enterprise.inject.spi.ProcessProducer;
import javax.inject.Provider;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.jboss.weld.bean.ProducerMethod;

/**
 * A CDI extension that provides a producer for the current authenticated JsonWebToken based on a thread
 * local value that is managed by the {@link org.eclipse.microprofile.jwt.wfswarm.JWTAuthMechanism} request
 * authentication handler.
 *
 * This also installs the producer methods for the discovered:
 * <ul>
 * <li>@Claim ClaimValue<T> injection sites.</li>
 * <li>@Claim raw type<T> injection sites.</li>
 * <li>@Claim JsonValue injection sites.</li>
 * </ul>
 *
 * @see org.eclipse.microprofile.jwt.wfswarm.JWTAuthMechanism
 */
public class MPJWTExtension implements Extension {
    /**
     * Register the MPJWTProducer JsonWebToken producer bean
     *
     * @param bbd         before discovery event
     * @param beanManager cdi bean manager
     */
    public void observeBeforeBeanDiscovery(@Observes BeforeBeanDiscovery bbd, BeanManager beanManager) {
        System.out.printf("MPJWTExtension(1.0.2), added JWTPrincipalProducer\n");
        bbd.addAnnotatedType(beanManager.createAnnotatedType(MPJWTProducer.class));
        //bbd.addAnnotatedType(beanManager.createAnnotatedType(CustomClaimProducer.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(RawClaimTypeProducer.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValueProducer.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(JsonValueProducer.class));
    }

    /**
     * Replace our xxx BeanAttributes with
     * yyyto properly reflect all of the type locations the producer method applies to.
     *
     * @param pba
     * @see xxx
     */
    public void addTypeToClaimProducer(@Observes ProcessBeanAttributes pba) {
        //System.out.printf("addTypeToClaimProducer, checking: %s\n", pba.getAnnotated());
        if (pba.getAnnotated().isAnnotationPresent(Claim.class)) {
            Claim claim = pba.getAnnotated().getAnnotation(Claim.class);
            if (claim.value().length() == 0 && claim.standard() == Claims.UNKNOWN) {
                System.out.printf("addTypeToClaimProducer: %s\n", pba.getAnnotated());
                BeanAttributes delegate = pba.getBeanAttributes();
                ProducerMethod method = null;
                if (delegate instanceof ProducerMethod) {
                    method = (ProducerMethod) delegate;
                }
                if (delegate.getTypes().contains(Optional.class)) {
                    if (providerOptionalTypes.size() == 0) {
                        providerOptionalTypes.add(Optional.class);
                    }
                    pba.setBeanAttributes(new ClaimProviderBeanAttributes(delegate, providerOptionalTypes, providerQualifiers));
                } else if (method != null && method.getBeanClass() == RawClaimTypeProducer.class) {
                    if (rawTypes.size() == 0) {
                        rawTypes.add(Object.class);
                    }
                    pba.setBeanAttributes(new ClaimProviderBeanAttributes(delegate, rawTypes, rawTypeQualifiers));
                    System.out.printf("Setup RawClaimTypeProducer BeanAttributes\n");
                } else {
                    /*
                    if(providerTypes.size() == 0) {
                        providerTypes.add(Object.class);
                    }
                    pba.setBeanAttributes(new ClaimProviderBeanAttributes(delegate, providerTypes, providerQualifiers));
                    */
                }
            }
        }
    }

    public void afterDeploymentValidation(@Observes AfterDeploymentValidation event, BeanManager beanManager) {
        System.err.println("afterDeploymentValidation");
    }

    void doProcessProducers(@Observes ProcessProducer pp) {
        System.out.printf("pp: %s, %s\n", pp.getAnnotatedMember(), pp.getProducer());
    }

    void processClaimValueInjections(@Observes ProcessInjectionPoint pip) {
        System.out.printf("pipRaw: %s\n", pip.getInjectionPoint());
        InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getAnnotated().isAnnotationPresent(Claim.class) && ip.getType() instanceof Class) {
            Class rawClass = (Class) ip.getType();
            if (Modifier.isFinal(rawClass.getModifiers())) {
                Claim claim = ip.getAnnotated().getAnnotation(Claim.class);
                rawTypes.add(ip.getType());
                rawTypeQualifiers.add(claim);
                System.out.printf("+++ Added Claim raw type: %s\n", ip.getType());
                Class declaringClass = ip.getMember().getDeclaringClass();
                Annotation[] appScoped = declaringClass.getAnnotationsByType(ApplicationScoped.class);
                Annotation[] sessionScoped = declaringClass.getAnnotationsByType(SessionScoped.class);
                if ((appScoped != null && appScoped.length > 0) || (sessionScoped != null && sessionScoped.length > 0)) {
                    String err = String.format("A raw type cannot be injected into application/session scope: IP=%s", ip);
                    pip.addDefinitionError(new DeploymentException(err));
                }

            }
        }
    }

    /**
     * Collect the types of all Provider injection points annotated with {@linkplain Claim}.
     *
     * @param pip - the injection point event information
     */
    void processClaimProviderInjections(@Observes ProcessInjectionPoint<?, Provider> pip) {
        System.out.printf("pip: %s\n", pip.getInjectionPoint());
        final InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getAnnotated().isAnnotationPresent(Claim.class)) {
            Claim claim = ip.getAnnotated().getAnnotation(Claim.class);
            if (claim.value().length() == 0 && claim.standard() == Claims.UNKNOWN) {
                throw new DeploymentException("@Claim at: " + ip + " has no name or valid standard enum setting");
            }
            boolean usesEnum = claim.standard() != Claims.UNKNOWN;
            final String claimName = usesEnum ? claim.standard().name() : claim.value();
            System.out.printf("Checking Provider Claim(%s), ip: %s\n", claimName, ip);
            ClaimIP claimIP = claims.get(claimName);
            Type matchType = ip.getType();
            Type actualType = ((ParameterizedType) matchType).getActualTypeArguments()[0];
            // Don't add Optional as this is handled specially
            if (!optionalOrJsonValue(actualType)) {
                rawTypes.add(actualType);
            } else if (!actualType.getTypeName().startsWith("javax.json.Json")) {
                providerOptionalTypes.add(actualType);
                providerQualifiers.add(claim);
            }
            rawTypeQualifiers.add(claim);
            ClaimIPType key = new ClaimIPType(claimName, actualType);
            if (claimIP == null) {
                claimIP = new ClaimIP(actualType, actualType, false, claim);
                claimIP.setProviderSite(true);
                claims.put(key, claimIP);
            }
            claimIP.getInjectionPoints().add(ip);
            System.out.printf("+++ Added Provider Claim(%s) ip: %s\n", claimName, ip);

        }
    }

    /**
     * Create producer methods for each ClaimValue injection site
     *
     * @param event       - AfterBeanDiscovery
     * @param beanManager - CDI bean manager
     */
    void observesAfterBeanDiscovery(@Observes final AfterBeanDiscovery event, final BeanManager beanManager) {
        System.out.printf("handleClaimInjections, %s\n", claims);
        installClaimValueProducerMethodsViaSyntheticBeans(event, beanManager);

        //installClaimValueProducesViaTemplateType(event, beanManager);
    }

    /**
     * Create a synthetic bean with a custom Producer for the non-Provider injection sites.
     *
     * @param event       - AfterBeanDiscovery
     * @param beanManager - CDI bean manager
     */
    private void installClaimValueProducerMethodsViaSyntheticBeans(final AfterBeanDiscovery event, final BeanManager beanManager) {

    }

    private boolean optionalOrJsonValue(Type type) {
        boolean isOptionOrJson = type.getTypeName().startsWith(Optional.class.getTypeName())
                | type.getTypeName().startsWith("javax.json.Json");
        return isOptionOrJson;
    }

    /**
     * A map of claim,type pairs to the injection site information
     */
    private HashMap<ClaimIPType, ClaimIP> claims = new HashMap<>();

    private AnnotatedType<ClaimValuesProducer> templateType;

    private Set<Type> providerOptionalTypes = new HashSet<>();

    private Set<Type> providerTypes = new HashSet<>();

    private Set<Type> rawTypes = new HashSet<>();

    private Set<Annotation> rawTypeQualifiers = new HashSet<>();

    private Set<Annotation> providerQualifiers = new HashSet<>();

    /**
     * A key for a claim,injection site type pair
     */
    public static class ClaimIPType implements Comparable<ClaimIPType> {
        public ClaimIPType(String claimName, Type ipType) {
            this.claimName = claimName;
            this.ipType = ipType;
        }

        /**
         * Order the @Claim ClaimValue<T> on the @Claim.value and then T type name
         *
         * @param o - ClaimIP to compare to
         * @return the ordering of this claim relative to o
         */
        @Override
        public int compareTo(ClaimIPType o) {
            int compareTo = claimName.compareTo(o.claimName);
            if (compareTo == 0) {
                compareTo = ipType.getTypeName().compareTo(o.ipType.getTypeName());
            }
            return compareTo;
        }

        private String claimName;

        private Type ipType;
    }

    /**
     * The representation of an @Claim annotated injection site
     */
    public static class ClaimIP {
        /**
         * Create a ClaimIP from the injection site information
         *
         * @param matchType  - the outer type of the injection site
         * @param valueType  - the parameterized type of the injection site
         * @param isOptional - is the injection site an Optional
         * @param claim      - the Claim qualifier
         */
        public ClaimIP(Type matchType, Type valueType, boolean isOptional, Claim claim) {
            this.matchType = matchType;
            this.valueType = valueType;
            this.claim = claim;
        }

        public Type getMatchType() {
            return matchType;
        }

        public String getClaimName() {
            return claim.standard() == Claims.UNKNOWN ? claim.value() : claim.standard().name();
        }

        public Claim getClaim() {
            return claim;
        }

        public Type getValueType() {
            return valueType;
        }

        public boolean isOptional() {
            return isOptional;
        }

        public boolean isProviderSite() {
            return isProviderSite;
        }

        public void setProviderSite(boolean providerSite) {
            this.isProviderSite = providerSite;
        }

        public boolean isNonStandard() {
            return isNonStandard;
        }

        public void setNonStandard(boolean nonStandard) {
            isNonStandard = nonStandard;
        }

        public boolean isJsonValue() {
            return isJsonValue;
        }

        public void setJsonValue(boolean jsonValue) {
            isJsonValue = jsonValue;
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

        /**
         * The injection site value type
         */
        private Type matchType;

        /**
         * The actual type of of the ParameterizedType matchType
         */
        private Type valueType;

        /**
         * Is valueType actually wrapped in an Optional
         */
        private boolean isOptional;

        private boolean isProviderSite;

        private boolean isNonStandard;

        private boolean isJsonValue;

        /**
         * The injection site @Claim annotation value
         */
        private Claim claim;

        /**
         * The location that share the @Claim/type combination
         */
        private HashSet<InjectionPoint> injectionPoints = new HashSet<>();
    }

}
