package org.eclipse.microprofile.jwt.wfswarm.cdi;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.BeforeBeanDiscovery;
import javax.enterprise.inject.spi.Extension;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.enterprise.inject.spi.ProcessInjectionPoint;
import javax.enterprise.inject.spi.ProcessProducer;

import org.eclipse.microprofile.jwt.JsonWebToken;

public class MPJWTExtension implements Extension {

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
    public void addJWTPrincipalProduer(@Observes BeforeBeanDiscovery bbd, BeanManager beanManager) {
        System.out.printf("MPJWTExtension, added JWTPrincipalProducer\n");
        bbd.addAnnotatedType(beanManager.createAnnotatedType(JWTPrincipalProducer.class));
    }
}
