package org.eclipse.microprofile.jwt.wfswarm.cdi;

import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.Producer;
import javax.enterprise.inject.spi.ProducerFactory;

/**
 * The ProducerFactory for JsonValueProducer
 */
public class JsonValueProducerFactory implements ProducerFactory<JsonValueProducer> {
    private MPJWTExtension.ClaimIP claimIP;
    JsonValueProducerFactory(MPJWTExtension.ClaimIP claimIP) {
        this.claimIP = claimIP;
    }

    @Override
    public <T> Producer<T> createProducer(Bean<T> bean) {
        return (Producer<T>) new JsonValueProducer(claimIP);
    }
}
