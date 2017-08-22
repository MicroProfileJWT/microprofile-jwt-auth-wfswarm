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
import javax.enterprise.util.AnnotationLiteral;
import javax.inject.Provider;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;

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
        private boolean isProducerSite;
        private boolean isNonStandard;
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
            this(matchType, valueType, isOptional, claim, false);
        }
        public ClaimIP(Type matchType, Type valueType, boolean isOptional, Claim claim, boolean isProducerSite) {
            this.matchType = matchType;
            this.valueType = valueType;
            this.claim = claim;
            this.isProducerSite = isProducerSite;
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

        public boolean isProducerSite() {
            return isProducerSite;
        }

        public boolean isNonStandard() {
            return isNonStandard;
        }

        public void setNonStandard(boolean nonStandard) {
            isNonStandard = nonStandard;
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

        /*
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerISS.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerSUB.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerAUD.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerEXP.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerIAT.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerJTI.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerUPN.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerGROUPS.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerRawToken.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerNBF.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerAuthTime.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerUpdatedAt.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerAZP.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerNONCE.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerAtHash.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerCHash.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerFullName.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerFamilyName.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerMiddleName.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerNICKNAME.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerGivenName.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerPreferredUsername.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerEMAIL.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerEmailVerified.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerGENDER.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerBIRTHDATE.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerZONEINFO.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerLOCALE.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerPhoneNumber.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerPhoneNumberVerified.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerADDRESS.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerACR.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerAMR.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerSubJwk.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerCNF.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerSipFromTag.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerSipDate.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerSipCallid.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerSipCseqNum.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerSipViaBranch.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerORIG.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerDEST.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerMKY.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerJWK.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerJWE.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerKID.class));
        bbd.addAnnotatedType(beanManager.createAnnotatedType(ClaimValuesProducerJKU.class));
*/
    }

    void doProcessProducers(@Observes ProcessProducer pp) {
        System.out.printf("pp: %s, %s\n", pp.getAnnotatedMember(), pp.getProducer());


    }
    void processClaimProducerInjections(@Observes ProcessInjectionPoint<?, Provider> pip) {
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
                claimIP = new ClaimIP(actualType, actualType, false, claim, true);
                claims.put(key, claimIP);
            }
            claimIP.getInjectionPoints().add(ip);
            System.out.printf("+++ Added Producer Claim(%s) ip: %s\n", claimName, ip);

            /*
            Set<Annotation> qualifiers = ip.getQualifiers();
            final HashSet<Annotation> override = new HashSet<>(qualifiers);
            if(!usesEnum) {
                override.remove(claim);
                override.add(new ClaimLiteral(){
                    public Claims standard() {
                        return Claims.valueOf(claimName);
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
            }
            */
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
            /*
            Set<Annotation> qualifiers = ip.getQualifiers();
            final HashSet<Annotation> override = new HashSet<>(qualifiers);
            if(!usesEnum) {
                // Validate that this maps to a Claims
                try {
                    final Claims standard = Claims.valueOf(claimName);
                    override.remove(claim);
                    override.add(new ClaimLiteral(){
                        public Claims standard() {
                            return Claims.valueOf(claimName);
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
                } catch (IllegalArgumentException e) {
                    // We have to generate a producer method
                    claimIP.setNonStandard(true);
                }
            }
            */
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
    void observesAfterBeanDiscovery(@Observes final AfterBeanDiscovery event, final BeanManager beanManager) {
        System.out.printf("handleClaimInjections, %s\n", claims);
        installClaimValueProducerMethodsViaSyntheticBeans(event, beanManager);
        //installClaimValueProducesViaTemplateType(event, beanManager);
    }

    /**
     *
     * @param event
     * @param beanManager
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
     *
     * @param event
     * @param beanManager
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
            if(!claimIP.isProducerSite() || claimIP.isNonStandard()) {
                // Pass in the ClaimIP so the producer knows the actual type
                ProducerFactory<ClaimValueProducer> factory = new ClaimValueProducerFactory(claimIP);
                // Create the BeanAttributes for the injection site producer method
                ClaimValueProducerBeanAttributes<ClaimValueProducer> methodAttributes = new ClaimValueProducerBeanAttributes<>(methodTypes, claimIP);
                // Create the producer method bean with the custom producer factory
                Bean<?> bean = beanManager.createBean(methodAttributes, ClaimValueProducer.class, factory);
                event.addBean(bean);
                System.out.printf("Added %s\n", bean);
            }
        }
    }
}
