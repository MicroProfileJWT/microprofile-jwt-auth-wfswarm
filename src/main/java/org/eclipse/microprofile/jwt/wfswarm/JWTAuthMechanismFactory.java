/*
 * Copyright (c) 2016-2017 Contributors to the Eclipse Foundation
 *
 *  See the NOTICE file(s) distributed with this work for additional
 *  information regarding copyright ownership.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  You may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.eclipse.microprofile.jwt.wfswarm;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.server.handlers.form.FormParserFactory;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.keycloak.common.util.PemUtils;

/**
 * A AuthenticationMechanismFactory for the MicroProfile JWT RBAC
 */
public class JWTAuthMechanismFactory implements AuthenticationMechanismFactory {
    /**
     * This builds the JWTAuthMechanism with a JWTAuthContextInfo containing the issuer and signer public key needed
     * to validate the token. This information is currently taken from the query parameters passed in via the
     * web.xml/login-config/auth-method value. We may need a better way to do this in the future.
     *
     * TODO: externalize the {@link JWTAuthContextInfo#getExpGracePeriodSecs()}
     *
     * @param mechanismName - the login-config/auth-method, which will be MP-JWT for JWTAuthMechanism
     * @param formParserFactory - unused form type of authentication factory
     * @param properties - the query parameters from the web.xml/login-config/auth-method value. We expect an issuedBy
     *                   and signerPubKey property to use for token validation.
     * @return the JWTAuthMechanism
     *
     * @see JWTAuthContextInfo
     */
    @Override
    public AuthenticationMechanism create(String mechanismName, FormParserFactory formParserFactory, Map<String, String> properties) {
        String issuedBy = properties.get("issuedBy");
        if(issuedBy == null) {
            throw new IllegalStateException("No issuedBy query parameter was found");
        }
        String publicKeyPemEnc = properties.get("signerPubKey");
        if(publicKeyPemEnc == null) {
            throw new IllegalStateException("No signerPubKey query parameter was found");
        }

        // Workaround the double decode issue; https://issues.jboss.org/browse/WFLY-9135
        String publicKeyPem = publicKeyPemEnc.replace(' ', '+');
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setIssuedBy(issuedBy);
        RSAPublicKey pk = (RSAPublicKey) PemUtils.decodePublicKey(publicKeyPem);
        contextInfo.setSignerKey(pk);

        return new JWTAuthMechanism(contextInfo);
    }
}
