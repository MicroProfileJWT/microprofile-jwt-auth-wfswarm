package org.eclipse.microprofile.jwt.wfswarm.cdi;

import java.lang.annotation.Annotation;
import java.lang.reflect.Member;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.AfterDeploymentValidation;
import javax.enterprise.inject.spi.Annotated;
import javax.enterprise.inject.spi.AnnotatedMethod;
import javax.enterprise.inject.spi.AnnotatedType;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanAttributes;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.InjectionTargetFactory;
import javax.enterprise.inject.spi.ProcessInjectionPoint;
import javax.enterprise.inject.spi.ProcessProducer;
import javax.enterprise.inject.spi.ProducerFactory;
import javax.inject.Provider;
import javax.json.JsonValue;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;

/**
 * A CDI extension that provides a producer for the current authenticated JsonWebToken based on a thread
 * local value that is managed by the {@link org.eclipse.microprofile.jwt.wfswarm.JWTAuthMechanism} request
 * authentication handler.
 *
 * This also installs the producer methods for the discovered:
 * <ul>
 *  <li>@Claim ClaimValue<T> injection sites.</li>
 *  <li>@Claim Provider<T> injection sites.</li>
 *  <li>@Claim JsonValue injection sites.</li>
 * </ul>
 *
 * @see org.eclipse.microprofile.jwt.wfswarm.JWTAuthMechanism
 */
public class MPJWTExtension implements Extension {
    /**
     * A key for a claim,injection site type pair
     */
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

    /**
     * The representation of an @Claim annotated injection site
     */
    public static class ClaimIP {
        /** The injection site value type */
        private Type matchType;
        /** The actual type of of the ParameterizedType matchType */
        private Type valueType;
        /** Is valueType actually wrapped in an Optional */
        private boolean isOptional;

        private boolean isProviderSite;
        private boolean isNonStandard;
        private boolean isJsonValue;
        /** The injection site @Claim annotation value */
        private Claim claim;
        /** The location that share the @Claim/type combination */
        private HashSet<InjectionPoint> injectionPoints = new HashSet<>();

        /**
         * Create a ClaimIP from the injection site information
         * @param matchType - the outer type of the injection site
         * @param valueType - the parameterized type of the injection site
         * @param isOptional - is the injection site an Optional
         * @param claim - the Claim qualifier
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
    }
    /** A map of claim,type pairs to the injection site information */
    private HashMap<ClaimIPType, ClaimIP> claims = new HashMap<>();
    private AnnotatedType<ClaimValuesProducer> templateType;

    /**
     * Register the MPJWTProducer JsonWebToken producer bean
     * @param bbd before discovery event
     * @param beanManager cdi bean manager
     */
    public void observeBeforeBeanDiscovery(@Observes BeforeBeanDiscovery bbd, BeanManager beanManager) {
        System.out.printf("MPJWTExtension, added JWTPrincipalProducer\n");
        bbd.addAnnotatedType(beanManager.createAnnotatedType(MPJWTProducer.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimsProviderProducer.class));
    }

    void doProcessProducers(@Observes ProcessProducer pp) {
        System.out.printf("pp: %s, %s\n", pp.getAnnotatedMember(), pp.getProducer());
    }

    /**
     * Collect the types of all JsonValue injection points annotated with {@linkplain Claim}.
     * @param pip - the injection point event information
     */
    void processClaimJsonValueInjections(@Observes ProcessInjectionPoint<?, ? extends JsonValue> pip) {
        System.out.printf("pip: %s\n", pip.getInjectionPoint());
        final InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getAnnotated().isAnnotationPresent(Claim.class)) {
            Claim claim = ip.getAnnotated().getAnnotation(Claim.class);
            if(claim.value().length() == 0 && claim.standard() == Claims.UNKNOWN) {
                throw new DeploymentException("@Claim at: "+ip+" has no name or valid standard enum setting");
            }
            boolean usesEnum = claim.standard() != Claims.UNKNOWN;
            final String claimName = usesEnum ? claim.standard().name() : claim.value();
            System.out.printf("Checking JsonValue Claim(%s), ip: %s\n", claimName, ip);
            ClaimIP claimIP = claims.get(claimName);
            Type matchType = ip.getType();
            ClaimIPType key = new ClaimIPType(claimName, matchType);
            if(claimIP == null) {
                claimIP = new ClaimIP(matchType, matchType, false, claim);
                claimIP.setJsonValue(true);
                claims.put(key, claimIP);
            }
            claimIP.getInjectionPoints().add(ip);
            System.out.printf("+++ Added JsonValue Claim(%s) ip: %s\n", claimName, ip);
        }
    }

    /**
     *
     * Collect the types of all Provider injection points annotated with {@linkplain Claim}.
     * @param pip - the injection point event information
     */
    void processClaimProviderInjections(@Observes ProcessInjectionPoint<?, Provider> pip) {
        System.out.printf("pip: %s\n", pip.getInjectionPoint());
        final InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getAnnotated().isAnnotationPresent(Claim.class)) {
            Claim claim = ip.getAnnotated().getAnnotation(Claim.class);
            if(claim.value().length() == 0 && claim.standard() == Claims.UNKNOWN) {
                throw new DeploymentException("@Claim at: "+ip+" has no name or valid standard enum setting");
            }
            boolean usesEnum = claim.standard() != Claims.UNKNOWN;
            final String claimName = usesEnum ? claim.standard().name() : claim.value();
            System.out.printf("Checking Producer Claim(%s), ip: %s\n", claimName, ip);
            ClaimIP claimIP = claims.get(claimName);
            Type matchType = ip.getType();
            Type actualType = ((ParameterizedType) matchType).getActualTypeArguments()[0];
            ClaimIPType key = new ClaimIPType(claimName, actualType);
            if(claimIP == null) {
                claimIP = new ClaimIP(actualType, actualType, false, claim);
                claimIP.setProviderSite(true);
                claims.put(key, claimIP);
            }
            claimIP.getInjectionPoints().add(ip);
            System.out.printf("+++ Added Provider Claim(%s) ip: %s\n", claimName, ip);


            /* The ClaimsProviderProducer methods only use the @Claim(standard=...) form of the
            qualifier, so if an injection site has used the string form, we override it's qualifier
            set here to use the standard form.
             */
            Set<Annotation> qualifiers = ip.getQualifiers();
            final HashSet<Annotation> override = new HashSet<>(qualifiers);
            if(!usesEnum) {
                try {
                    final Claims claimType = Claims.valueOf(claimName);
                    override.remove(claim);
                    override.add(new ClaimLiteral(){
                        public Claims standard() {
                            return claimType;
                        }
                    });
                    pip.setInjectionPoint(new InjectionPoint() {
                        @Override
                        public Type getType() {
                            return ip.getType();
                        }

                        @Override
                        public Set<Annotation> getQualifiers() {
                            return override;
                        }

                        @Override
                        public Bean<?> getBean() {
                            return ip.getBean();
                        }

                        @Override
                        public Member getMember() {
                            return ip.getMember();
                        }

                        @Override
                        public Annotated getAnnotated() {
                            return ip.getAnnotated();
                        }

                        @Override
                        public boolean isDelegate() {
                            return ip.isDelegate();
                        }

                        @Override
                        public boolean isTransient() {
                            return ip.isTransient();
                        }
                    });
                } catch(IllegalArgumentException e) {
                    // A non-standard claim,
                    claimIP.setNonStandard(true);
                }
            }
        }
    }
    /**
     * Collect the types of all ClaimValue injection points annotated with {@linkplain Claim}.
     * @param pip - the injection point event information
     */
    void processInjection(@Observes ProcessInjectionPoint<?, ClaimValue> pip) {
        System.out.printf("processInjection: %s\n", pip.getInjectionPoint());
        InjectionPoint ip = pip.getInjectionPoint();
        if (ip.getAnnotated().isAnnotationPresent(Claim.class)) {
            Claim claim = ip.getAnnotated().getAnnotation(Claim.class);
            if(claim.value().length() == 0 && claim.standard() == Claims.UNKNOWN) {
                throw new DeploymentException("@Claim at: "+ip+" has no name or valie standard enum setting");
            }
            boolean usesEnum = claim.standard() != Claims.UNKNOWN;
            final String claimName = usesEnum ? claim.standard().name() : claim.value();
            System.out.printf("Checking Claim(%s), ip: %s\n", claimName, ip);
            ClaimIP claimIP = claims.get(claimName);
            ClaimIPType key = new ClaimIPType(claimName, ip.getType());
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
            System.out.printf("+++ Added Claim(%s) ip: %s\n", claimName, ip);
        }
    }

    public void afterDeploymentValidation(@Observes AfterDeploymentValidation event, BeanManager beanManager) {
        System.err.println("afterDeploymentValidation");
    }

    /**
     * Create producer methods for each ClaimValue injection site
     * @param event - AfterBeanDiscovery
     * @param beanManager - CDI bean manager
     */
    void observesAfterBeanDiscovery(@Observes final AfterBeanDiscovery event, final BeanManager beanManager) {
        System.out.printf("handleClaimInjections, %s\n", claims);
        installClaimValueProducerMethodsViaSyntheticBeans(event, beanManager);
        //installClaimValueProducesViaTemplateType(event, beanManager);
    }

    /**
     * Currently unused prototype code.
     * @param event - AfterBeanDiscovery
     * @param beanManager - CDI bean manager
     */
    private void installClaimValueProducesViaTemplateType(final AfterBeanDiscovery event, final BeanManager beanManager) {
        BeanAttributes<ClaimValuesProducer> ba = beanManager.createBeanAttributes(templateType);
        InjectionTargetFactory<ClaimValuesProducer> templateITF = beanManager.getInjectionTargetFactory(templateType);
        Bean<ClaimValuesProducer> templateBean = beanManager.createBean(ba, ClaimValuesProducer.class, templateITF);
        for(AnnotatedMethod<? super ClaimValuesProducer> am : templateType.getMethods()) {
            ProducerFactory<ClaimValuesProducer> factory = beanManager.getProducerFactory(am, templateBean);
            System.out.printf("\tBaseType:%s\n", am.getBaseType());
            System.out.printf("\tAnnotations:%s\n", am.getAnnotations());
            System.out.printf("\tIP:%s\n", factory.createProducer(templateBean).getInjectionPoints());
        }

        // For each @Claim injection point type, add a producer method
        for (final ClaimIP claimIP : claims.values()) {

            DelegateAnnType typeForClaim = new DelegateAnnType(claimIP.claim, templateType);
            BeanAttributes<ClaimValuesProducer> attributes = beanManager.createBeanAttributes(typeForClaim);
            InjectionTargetFactory<ClaimValuesProducer> itf = beanManager.getInjectionTargetFactory(typeForClaim);
            Bean<ClaimValuesProducer> bean = beanManager.createBean(attributes, ClaimValuesProducer.class, itf);
            event.addBean(bean);
            System.out.printf("Added %s\n", bean);
            Set<AnnotatedMethod<? super ClaimValuesProducer>> methods = typeForClaim.getMethods();
            for(AnnotatedMethod<? super ClaimValuesProducer> am : methods) {
                ProducerFactory<ClaimValuesProducer> factory = beanManager.getProducerFactory(am, bean);
                System.out.printf("\tBaseType:%s\n", am.getBaseType());
                System.out.printf("\tAnnotations:%s\n", am.getAnnotations());
                System.out.printf("\tIP:%s\n", factory.createProducer(bean).getInjectionPoints());
            }
        }
    }

    /**
     * Create a synthetic bean with a custom Producer for the non-Provider injection sites.
     * @param event - AfterBeanDiscovery
     * @param beanManager - CDI bean manager
     */
    private void installClaimValueProducerMethodsViaSyntheticBeans(final AfterBeanDiscovery event, final BeanManager beanManager) {
        // For each non-standard @Claim injection point type, add a producer method
        for (final ClaimIP claimIP : claims.values()) {
            /*
            if(!claimIP.isNonStandard()) {
                continue;
            }
            */

            // Use the ClaimIP#matchType as the type against the producer method will be matched
            HashSet<Type> methodTypes = new HashSet<>();
            methodTypes.add(claimIP.matchType);
            if(claimIP.isJsonValue()) {
                // Pass in the ClaimIP so the producer knows the actual type
                ProducerFactory<JsonValueProducer> factory = new JsonValueProducerFactory(claimIP);
                // Create the BeanAttributes for the injection site producer method
                ValueProducerBeanAttributes<JsonValueProducer> methodAttributes = new ValueProducerBeanAttributes<>(methodTypes, claimIP);
                // Create the producer method bean with the custom producer factory
                Bean<?> bean = beanManager.createBean(methodAttributes, JsonValueProducer.class, factory);
                event.addBean(bean);
                System.out.printf("Added %s\n", bean);
            }
            else if(!claimIP.isProviderSite() || claimIP.isNonStandard()) {
                // Pass in the ClaimIP so the producer knows the actual type
                ProducerFactory<ClaimValueProducer> factory = new ClaimValueProducerFactory(claimIP);
                // Create the BeanAttributes for the injection site producer method
                ValueProducerBeanAttributes<ClaimValueProducer> methodAttributes = new ValueProducerBeanAttributes<>(methodTypes, claimIP);
                // Create the producer method bean with the custom producer factory
                Bean<?> bean = beanManager.createBean(methodAttributes, ClaimValueProducer.class, factory);
                event.addBean(bean);
                System.out.printf("Added %s\n", bean);
            }
        }
    }
}
