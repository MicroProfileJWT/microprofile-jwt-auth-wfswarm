package org.eclipse.microprofile.jwt.wfswarm.cdi;

import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.Producer;
import javax.enterprise.inject.spi.ProducerFactory;

/**
 * The ProducerFactory for RawClaimProducer
 *
 * @param <T>
 */
public class RawClaimProducerFactory<T> implements ProducerFactory<RawClaimProducer> {
    RawClaimProducerFactory(MPJWTExtension.ClaimIP claimIP) {
        this.claimIP = claimIP;
    }

    @Override
    public <T1> Producer<T1> createProducer(Bean<T1> bean) {
        return new RawClaimProducer(claimIP);
    }

    private MPJWTExtension.ClaimIP claimIP;
}
