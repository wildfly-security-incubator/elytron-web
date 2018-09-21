/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.elytron.web.jetty.server;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.wildfly.security.password.interfaces.ClearPassword.ALGORITHM_CLEAR;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import org.eclipse.jetty.security.ConstraintMapping;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletHandler;
import org.eclipse.jetty.util.security.Constraint;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.wildfly.common.iteration.ByteIterator;
import org.wildfly.security.WildFlyElytronProvider;
import org.wildfly.security.auth.permission.LoginPermission;
import org.wildfly.security.auth.realm.SimpleMapBackedSecurityRealm;
import org.wildfly.security.auth.realm.SimpleRealmEntry;
import org.wildfly.security.auth.server.MechanismConfiguration;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.MechanismRealmConfiguration;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.RoleDecoder;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;
import org.wildfly.security.http.util.FilterServerMechanismFactory;
import org.wildfly.security.http.util.SecurityProviderServerMechanismFactory;
import org.wildfly.security.password.PasswordFactory;
import org.wildfly.security.password.spec.ClearPasswordSpec;
import org.wildfly.security.permission.PermissionVerifier;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Tests for HTTP BASIC authentication where authentication is backed by Elytron.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class BasicAuthenticationTest {

    private static final WildFlyElytronProvider ELYTRON_PROVIDER = new WildFlyElytronProvider();
    private static final String WWW_AUTHENTICATE = "WWW-Authenticate";
    private static final String AUTHORIZATION = "Authorization";
    private static final String BASIC = "Basic";
    private static final String ELYTRON_USER = "ElytronUser";
    private static final int PORT = 7776;
    private static Server server;
    private static SecurityDomain securityDomain;

    @BeforeClass
    public static void setUp() throws Exception {
        Security.addProvider(ELYTRON_PROVIDER);
        server = new Server(PORT);
        ConstraintSecurityHandler security = new ConstraintSecurityHandler();
        server.setHandler(security);

        // Create a constraint that specifies that accessing "/secured" requires authentication
        // and the authenticated user must have "admin" role
        Constraint constraint = new Constraint();
        constraint.setName("auth");
        constraint.setAuthenticate(true);
        constraint.setRoles(new String[]{"admin"});
        ConstraintMapping mapping = new ConstraintMapping();
        mapping.setPathSpec("/secured");
        mapping.setConstraint(constraint);
        security.setConstraintMappings(Collections.singletonList(mapping));

        // Specify that authentication should be handled by ElytronAuthenticator
        HttpServerAuthenticationMechanismFactory providerFactory = new SecurityProviderServerMechanismFactory(() -> new Provider[] {new WildFlyElytronProvider()});
        HttpServerAuthenticationMechanismFactory httpServerMechanismFactory = new FilterServerMechanismFactory(providerFactory, true, "BASIC");
        securityDomain = createSecurityDomain();
        ElytronAuthenticator elytronAuthenticator = ElytronAuthenticator.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismConfigurationSelector(MechanismConfigurationSelector.constantSelector(
                        MechanismConfiguration.builder()
                                .addMechanismRealm(MechanismRealmConfiguration.builder().setRealmName("Elytron Realm").build())
                                .build()))
                .setFactory(httpServerMechanismFactory)
                .build();
        security.setAuthenticator(elytronAuthenticator);

        ServletHandler servletHandler = new ServletHandler();
        ElytronRunAsHandler elytronRunAsHandler = new ElytronRunAsHandler(servletHandler);
        servletHandler.addServletWithMapping(SecuredServlet.class, "/secured");
        security.setHandler(elytronRunAsHandler);

        server.start();
    }

    @AfterClass
    public static void cleanUp() throws Exception {
        Security.removeProvider(ELYTRON_PROVIDER.getName());
        server.stop();
    }

    @Test
    public void testUnauthorized() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(getURI());
        assertUnauthorizedResponse(httpClient.execute(get));
    }

    @Test
    public void testSuccessfulAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(getURI());

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + ByteIterator.ofBytes("alice:alice123+".getBytes(StandardCharsets.US_ASCII)).base64Encode().drainToString());

        HttpResponse result = httpClient.execute(get);
        assertEquals(HttpServletResponse.SC_OK, result.getStatusLine().getStatusCode());
        assertSuccessfulResponse(result, "alice");
    }

    @Test
    public void testFailedAuthentication() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(getURI());

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + ByteIterator.ofBytes("alice:wrongpassword".getBytes(StandardCharsets.US_ASCII)).base64Encode().drainToString());
        assertUnauthorizedResponse(httpClient.execute(get));
    }

    @Test
    public void testSuccessfulAuthenticationFailedAuthorization() throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet get = new HttpGet(getURI());

        get.addHeader(AUTHORIZATION.toString(), BASIC + " " + ByteIterator.ofBytes("bob:bob123+".getBytes(StandardCharsets.US_ASCII)).base64Encode().drainToString());
        assertEquals(HttpServletResponse.SC_FORBIDDEN, httpClient.execute(get).getStatusLine().getStatusCode());
    }

    private static SecurityDomain createSecurityDomain() throws Exception {

        // Create an Elytron map-backed security realm
        SimpleMapBackedSecurityRealm simpleRealm = new SimpleMapBackedSecurityRealm(() -> new Provider[] { ELYTRON_PROVIDER });
        Map<String, SimpleRealmEntry> identityMap = new HashMap<>();

        // Add user alice
        identityMap.put("alice", new SimpleRealmEntry(getCredentialsForClearPassword("alice123+"), getAttributesForRoles("employee", "admin")));

        // Add user bob
        identityMap.put("bob", new SimpleRealmEntry(getCredentialsForClearPassword("bob123+"), getAttributesForRoles("employee")));
        simpleRealm.setIdentityMap(identityMap);

        // Add the map-backed security realm to a new security domain's list of realms
        SecurityDomain.Builder builder = SecurityDomain.builder()
                .addRealm("ExampleRealm", simpleRealm).build()
                .setPermissionMapper((principal, roles) -> PermissionVerifier.from(new LoginPermission()))
                .setDefaultRealmName("ExampleRealm");

        return builder.build();
    }

    private static List<Credential> getCredentialsForClearPassword(String clearPassword) throws Exception {
        PasswordFactory passwordFactory = PasswordFactory.getInstance(ALGORITHM_CLEAR, ELYTRON_PROVIDER);
        return Collections.singletonList(new PasswordCredential(passwordFactory.generatePassword(new ClearPasswordSpec(clearPassword.toCharArray()))));
    }

    private static MapAttributes getAttributesForRoles(String... roles) {
        MapAttributes attributes = new MapAttributes();
        HashSet<String> rolesSet = new HashSet<>();
        if (roles != null) {
            for (String role : roles) {
                rolesSet.add(role);
            }
        }
        attributes.addAll(RoleDecoder.KEY_ROLES, rolesSet);
        return attributes;
    }

    public static class SecuredServlet extends HttpServlet {

        protected void doGet(
                HttpServletRequest request,
                HttpServletResponse response)
                throws ServletException, IOException {

            response.setContentType("text/html");
            response.setStatus(HttpServletResponse.SC_OK);
            response.setHeader(ELYTRON_USER, getElytronUser());
        }
    }

    private URI getURI() throws Exception {
        return new URI("http", null, "localhost", PORT, "/secured", null, null);
    }

    private void assertUnauthorizedResponse(HttpResponse result) {
        assertEquals(HttpServletResponse.SC_UNAUTHORIZED, result.getStatusLine().getStatusCode());

        Header wwwAuthenticateHeader = result.getFirstHeader(WWW_AUTHENTICATE.toString());
        assertNotNull(wwwAuthenticateHeader);
        assertEquals("Basic realm=\"Elytron Realm\"", wwwAuthenticateHeader.getValue());
    }

    private static String getElytronUser() {
        if (securityDomain != null) {
            SecurityIdentity securityIdentity = securityDomain.getCurrentSecurityIdentity();
            if (securityIdentity != null) {
                return securityIdentity.getPrincipal().getName();
            }
        }

        return null;
    }

    private void assertSuccessfulResponse(HttpResponse result, String expectedUserName) {
        Header[] values = result.getHeaders(ELYTRON_USER);
        assertEquals(1, values.length);
        assertEquals(expectedUserName, values[0].getValue());
    }
}
