package org.eclipse.microprofile.jwt.wfswarm.cdi;

import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.Producer;
import javax.enterprise.inject.spi.ProducerFactory;

import org.eclipse.microprofile.jwt.ClaimValue;

/**
 * The ProducerFactory for ClaimValueProducer
 */
public class ClaimValueProducerFactory implements ProducerFactory<ClaimValueProducer> {
    private MPJWTExtension.ClaimIP claimIP;
    ClaimValueProducerFactory(MPJWTExtension.ClaimIP claimIP) {
        this.claimIP = claimIP;
    }
    @Override
    public <T1> Producer<T1> createProducer(Bean<T1> bean) {
        return new ClaimValueProducer(claimIP);
    }
}
