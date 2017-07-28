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

import java.security.Principal;
import java.security.acl.Group;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.security.auth.Subject;

import io.undertow.UndertowLogger;
import io.undertow.security.api.AuthenticationMechanism;
import io.undertow.security.api.SecurityContext;
import io.undertow.server.HttpServerExchange;
import org.eclipse.microprofile.jwt.principal.JWTAuthContextInfo;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.ParseException;
import org.jboss.security.SecurityConstants;
import org.jboss.security.SecurityContextAssociation;
import org.jboss.security.SimpleGroup;
import org.jboss.security.SimplePrincipal;
import org.jboss.security.identity.RoleGroup;
import org.jboss.security.identity.plugins.SimpleRoleGroup;

import static io.undertow.util.Headers.AUTHORIZATION;
import static io.undertow.util.Headers.WWW_AUTHENTICATE;
import static io.undertow.util.StatusCodes.UNAUTHORIZED;

/**
 * An AuthenticationMechanism that validates a caller based on a MicroProfile JWT bearer token
 */
public class JWTAuthMechanism implements AuthenticationMechanism {
    private JWTAuthContextInfo authContextInfo;

    public JWTAuthMechanism(JWTAuthContextInfo authContextInfo) {
        this.authContextInfo = authContextInfo;
    }

    /**
     * Extract the Authorization header and validate the bearer token if it exists. If it does, and is validated, this
     * builds the org.jboss.security.SecurityContext authenticated Subject that drives the container APIs as well as
     * the authorization layers.
     * @param exchange - the http request exchange object
     * @param securityContext - the current security context that
     * @return one of AUTHENTICATED, NOT_AUTHENTICATED or NOT_ATTEMPTED depending on the header and authentication outcome.
     */
    @Override
    public AuthenticationMechanismOutcome authenticate(HttpServerExchange exchange, SecurityContext securityContext) {
        List<String> authHeaders = exchange.getRequestHeaders().get(AUTHORIZATION);
        if (authHeaders != null) {
            String bearerToken = null;
            for (String current : authHeaders) {
                if (current.toLowerCase(Locale.ENGLISH).startsWith("bearer ")) {
                    bearerToken = current.substring(7);
                    if(UndertowLogger.SECURITY_LOGGER.isTraceEnabled())
                        UndertowLogger.SECURITY_LOGGER.tracef("Bearer token: %s", bearerToken);
                    try {
                        JWTCallerPrincipal jwtPrincipal = validate(bearerToken);
                        if(UndertowLogger.SECURITY_LOGGER.isTraceEnabled())
                            UndertowLogger.SECURITY_LOGGER.tracef("Bearer token: %s", jwtPrincipal);
                        // Install the JWT principal as the caller
                        JWTAccount account = new JWTAccount(jwtPrincipal);
                        securityContext.authenticationComplete(account, "MP-JWT", false);
                        /* We have to update the wildfly SecurityContext with an authenticated subject view in order for
                            all of the container APIs and authorization layers to operate on the token authorization
                            information.
                        */
                        Subject subject = new Subject();
                        RoleGroup roles = commit(subject, jwtPrincipal);
                        org.jboss.security.SecurityContext jbSC = SecurityContextAssociation.getSecurityContext();
                        jbSC.getUtil().createSubjectInfo(jwtPrincipal, bearerToken, subject);
                        jbSC.getUtil().setRoles(roles);
                        return AuthenticationMechanismOutcome.AUTHENTICATED;
                    } catch (Exception e) {
                        UndertowLogger.SECURITY_LOGGER.debugf(e, "Failed to validate JWT bearer token");
                        return AuthenticationMechanismOutcome.NOT_AUTHENTICATED;
                    }
                }
            }
        }

        // No suitable header has been found in this request,
        return AuthenticationMechanismOutcome.NOT_ATTEMPTED;
    }

    @Override
    public ChallengeResult sendChallenge(HttpServerExchange exchange, SecurityContext securityContext) {
        exchange.getResponseHeaders().add(WWW_AUTHENTICATE, "Bearer {token}");
        UndertowLogger.SECURITY_LOGGER.debugf("Sending Bearer {token} challenge for %s", exchange);
        return new ChallengeResult(true, UNAUTHORIZED);
    }

    /**
     * Validate the bearer token passed in with the authorization header
     * @param bearerToken - the input bearer token
     * @return return the validated JWTCallerPrincipal
     * @throws ParseException - thrown on token parse or validation failure
     */
    protected JWTCallerPrincipal validate(String bearerToken) throws ParseException {
        JWTCallerPrincipalFactory factory = JWTCallerPrincipalFactory.instance();
        JWTCallerPrincipal callerPrincipal = factory.parse(bearerToken, authContextInfo);
        return callerPrincipal;
    }

    /**
     * Called to populate the SecurityContext Subject with the identify and roles from the validated JWTCallerPrincipal
     * @param subject - the SecurityContext Subject that is used by the containers
     * @param identity - the validated JWTCallerPrincipal
     * @return a RoleGroup summary of the roles associated with the Subject as this is used by the SecurityContext
     *  SubjectInfo and used by authorization layers of the containers
     */
    protected RoleGroup commit(Subject subject, JWTCallerPrincipal identity) {
        Set<Principal> principals = subject.getPrincipals();
        principals.add(identity);
        // Add the roles and groups from the token
        SimpleGroup rolesGroup = new SimpleGroup("Roles");
        for(String role : identity.getRoles()) {
            rolesGroup.addMember(new SimplePrincipal(role));
        }
        for(String group : identity.getGroups()) {
            principals.add(new SimpleGroup(group));
        }
        principals.add(rolesGroup);
        // add the CallerPrincipal group if none has been added in getRoleSets
        Group callerGroup = getCallerPrincipalGroup(principals);
        if (callerGroup == null) {
            callerGroup = new SimpleGroup(SecurityConstants.CALLER_PRINCIPAL_GROUP);
            callerGroup.addMember(identity);
            principals.add(callerGroup);
        }
        RoleGroup roles = new SimpleRoleGroup( rolesGroup );
        return roles;
    }

    /**
     * Get the "CallerPrincipal" Group from the set of Subject principals
     * @param principals - subject principals set to search
     * @return the CallerPrincipal group if it exists, null otherwise
     */
    private Group getCallerPrincipalGroup(Set<Principal> principals) {
        Group callerGroup = null;
        for (Principal principal : principals) {
            if (principal instanceof Group) {
                Group group = Group.class.cast(principal);
                if (group.getName().equals(SecurityConstants.CALLER_PRINCIPAL_GROUP)) {
                    callerGroup = group;
                    break;
                }
            }
        }
        return callerGroup;
    }
}
