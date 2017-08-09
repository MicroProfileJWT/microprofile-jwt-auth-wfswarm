package org.eclipse.microprofile.jwt.wfswarm.jaas;

import io.undertow.security.idm.Credential;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;

/**
 *
 */
public class JWTCredential implements Credential {
    private JWTAuthContextInfo authContextInfo;
    private String bearerToken;
    private String name;
    private Exception jwtException;

    public JWTCredential(String bearerToken, JWTAuthContextInfo authContextInfo) {
        this.bearerToken = bearerToken;
        this.authContextInfo = authContextInfo;
    }

    public String getName() {
        if(name == null) {
            try {
                // Build a JwtConsumer that doesn't check signatures or do any validation.
                JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
                        .setSkipAllValidators()
                        .setDisableRequireSignature()
                        .setSkipSignatureVerification()
                        .build();

                //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.
                JwtContext jwtContext = firstPassJwtConsumer.process(bearerToken);
                JwtClaims claimsSet = jwtContext.getJwtClaims();
                // We have to determine the unique name to use as the principal name. It comes from upn, preferred_username, sub in that order
                name = claimsSet.getClaimValue("upn", String.class);
                if(name == null) {
                    name = claimsSet.getClaimValue("preferred_username", String.class);
                    if(name == null) {
                        name = claimsSet.getSubject();
                    }
                }
            } catch (Exception e) {
                jwtException = e;
            }
        }
        return name;
    }
    public String getBearerToken() {
        return bearerToken;
    }
    public JWTAuthContextInfo getAuthContextInfo() {
        return authContextInfo;
    }

    public Exception getJwtException() {
        return jwtException;
    }
}
