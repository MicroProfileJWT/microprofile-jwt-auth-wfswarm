package org.eclipse.microprofile.jwt.test.jaxrs;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;

import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.Extension;
import javax.security.enterprise.CallerPrincipal;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import io.undertow.servlet.ServletExtension;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.impl.DefaultJWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipal;
import org.eclipse.microprofile.jwt.principal.JWTCallerPrincipalFactory;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.eclipse.microprofile.jwt.wfswarm.JWTAuthMethodExtension;
import org.eclipse.microprofile.jwt.wfswarm.cdi.MPJWTExtension;
import org.eclipse.microprofile.jwt.wfswarm.cdi.TCKApplication;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.container.test.api.ShouldThrowException;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.maven.ConfigurableMavenResolverSystem;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.testng.Assert;
import org.testng.annotations.Test;

import static javax.ws.rs.core.MediaType.TEXT_PLAIN;

public class AppScopedTest extends Arquillian {
    /**
     * The base URL for the container under test
     */
    @ArquillianResource
    private URL baseURL;

    /**
     * Create a CDI aware base web application archive
     * @return the base base web application archive
     * @throws IOException - on resource failure
     */
    @Deployment(testable=true)
    @ShouldThrowException(DeploymentException.class)
    public static WebArchive createDeployment() throws IOException {
        //System.setProperty("swarm.resolver.offline", "true");
       // System.setProperty("swarm.debug.port", "8888");
        //System.setProperty("org.jboss.weld.development", "true");
        //System.setProperty("org.jboss.weld.probe.exportDataAfterDeployment", "/tmp/cdi.out");
        ConfigurableMavenResolverSystem resolver = Maven.configureResolver().workOffline();
        File wfswarmauth = resolver.resolve("org.eclipse.microprofile.jwt:jwt-auth-wfswarm:1.0-SNAPSHOT").withoutTransitivity().asSingleFile();
        File[] resteasy = resolver.resolve("org.jboss.resteasy:resteasy-json-p-provider:3.0.6.Final").withTransitivity().asFile();
        File[] ri = resolver.resolve("org.eclipse.microprofile.jwt:jwt-auth-principal-prototype:1.0-SNAPSHOT").withTransitivity().asFile();
        URL publicKey = RolesAllowedTest.class.getResource("/publicKey.pem");
        WebArchive webArchive = ShrinkWrap
                .create(WebArchive.class, "AppScopedTest.war")
                .addAsLibraries(wfswarmauth)
                .addAsLibraries(ri)
                .addAsLibraries(resteasy)
                .addAsResource(publicKey, "/publicKey.pem")
                .addAsManifestResource(publicKey, "/MP-JWT-SIGNER")
                .addAsResource("project-defaults.yml", "/project-defaults.yml")
                .addPackage(JWTCallerPrincipal.class.getPackage())
                .addClass(AppScopedEndpoint.class)
                .addClass(TCKApplication.class)
                .addClass(JsonWebToken.class)
                .addClass(CallerPrincipal.class)

                .addAsServiceProvider(JWTCallerPrincipalFactory.class, DefaultJWTCallerPrincipalFactory.class)
                .addAsServiceProvider(ServletExtension.class, JWTAuthMethodExtension.class)
                .addAsServiceProvider(Extension.class, MPJWTExtension.class)
                .addAsWebInfResource("beans.xml", "beans.xml")
                .addAsWebInfResource("jwt-roles.properties", "classes/jwt-roles.properties")
                .addAsWebInfResource("WEB-INF/web.xml", "web.xml")
                .addAsWebInfResource("WEB-INF/jboss-web.xml", "jboss-web.xml")
                ;
        System.out.printf("WebArchive: %s\n", webArchive.toString(true));
        return webArchive;
    }

    @Test
    @RunAsClient
    public void verifyDeploymentException() throws Exception {
        HashSet<TokenUtils.InvalidClaims> invalidFields = new HashSet<>();
        invalidFields.add(TokenUtils.InvalidClaims.EXP);
        String token = TokenUtils.generateTokenString("/RolesEndpoint.json", invalidFields);

        String uri = baseURL.toExternalForm() + "/endp/verify";
        WebTarget echoEndpointTarget = ClientBuilder.newClient()
                .target(uri)
                ;
        Response response = echoEndpointTarget.request(TEXT_PLAIN).header(HttpHeaders.AUTHORIZATION, "Bearer "+token).get();
        Assert.assertEquals(response.getStatus(), HttpURLConnection.HTTP_INTERNAL_ERROR);
    }
}
