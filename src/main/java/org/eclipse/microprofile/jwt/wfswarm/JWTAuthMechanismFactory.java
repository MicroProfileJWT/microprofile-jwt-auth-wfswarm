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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.AuthenticationMechanismFactory;
import io.undertow.server.handlers.form.FormParserFactory;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.jboss.logging.Logger;

/**
 * A AuthenticationMechanismFactory for the MicroProfile JWT RBAC
 */
public class JWTAuthMechanismFactory implements AuthenticationMechanismFactory {
    private static Logger log = Logger.getLogger(JWTAuthMechanismFactory.class);

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
        ClassLoader loader = Thread.currentThread().getContextClassLoader();

        String issuedBy = properties.get("issuedBy");
        if(issuedBy == null) {
            // Try the /META-INF/MP-JWT-ISSUER content
            URL issURL = loader.getResource("/META-INF/MP-JWT-ISSUER");
            if(issURL == null)
                throw new IllegalStateException("No issuedBy parameter was found");
            issuedBy = readURLContent(issURL);
        }
        String publicKeyPemEnc = properties.get("signerPubKey");
        if(publicKeyPemEnc == null) {
            // Try the /META-INF/MP-JWT-SIGNER content
            URL pkURL = loader.getResource("/META-INF/MP-JWT-SIGNER");
            if(pkURL == null)
                throw new IllegalStateException("No signerPubKey parameter was found");
            publicKeyPemEnc = readURLContent(pkURL);
        }

        // Workaround the double decode issue; https://issues.jboss.org/browse/WFLY-9135
        String publicKeyPem = publicKeyPemEnc.replace(' ', '+');
        JWTAuthContextInfo contextInfo = new JWTAuthContextInfo();
        contextInfo.setIssuedBy(issuedBy);
        try {
            RSAPublicKey pk = (RSAPublicKey) KeyUtils.decodePublicKey(publicKeyPem);
            contextInfo.setSignerKey(pk);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }

        return new JWTAuthMechanism(contextInfo);
    }

    private String readURLContent(URL url) {
        StringBuilder content = new StringBuilder();
        try {
            InputStream is = url.openStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(is));
            String line = reader.readLine();
            while(line != null) {
                content.append(line);
                content.append('\n');
                line = reader.readLine();
            }
            reader.close();
        } catch (IOException e) {
            log.warnf("Failed to read content from: %s, error=%s", url, e.getMessage());
        }
        return content.toString();
    }
}
