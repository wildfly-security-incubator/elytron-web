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

import org.eclipse.jetty.http.HttpCookie;
import org.eclipse.jetty.security.AbstractLoginService;
import org.eclipse.jetty.security.DefaultUserIdentity;
import org.eclipse.jetty.security.UserAuthentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.eclipse.jetty.server.UserIdentity;
import org.wildfly.security.auth.server.SecurityIdentity;
import org.wildfly.security.authz.Roles;
import org.wildfly.security.credential.Credential;
import org.wildfly.security.credential.KeyPairCredential;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.SecretKeyCredential;
import org.wildfly.security.credential.X509CertificateChainPrivateCredential;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpExchangeSpi;
import org.wildfly.security.http.HttpScope;
import org.wildfly.security.http.HttpServerCookie;
import org.wildfly.security.http.Scope;

import javax.security.auth.Subject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;


/**
 * Implementation of {@link HttpExchangeSpi} for integration with Jetty.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronHttpExchange implements HttpExchangeSpi {

    private final Request request;
    private final Response response;

    /**
     * Construct a new instance.
     *
     * @param request the request
     * @param response the response
     */
    public ElytronHttpExchange(Request request, Response response) {
        this.request = request;
        this.response = response;
    }

    @Override
    public List<String> getRequestHeaderValues(String headerName) {
        Enumeration<String> headerEnum = this.request.getHeaders(headerName);

        if (headerEnum == null) {
            return Collections.emptyList();
        }

        List<String> values = new ArrayList<>();

        while (headerEnum.hasMoreElements()) {
            values.add(headerEnum.nextElement());
        }

        return Collections.unmodifiableList(values);
    }

    @Override
    public void addResponseHeader(String headerName, String headerValue) {
        this.response.addHeader(headerName, headerValue);
    }


    @Override
    public void setStatusCode(int statusCode) {
        response.setStatus(statusCode);
    }

    @Override
    public void authenticationComplete(SecurityIdentity securityIdentity, String mechanismName) {
        Subject subject = new Subject();
        Principal principal = securityIdentity.getPrincipal();
        subject.getPrincipals().add(principal);
        addPrivateCredentials(subject, securityIdentity);
        Roles roles = securityIdentity.getRoles();
        ArrayList<String> rolesList = new ArrayList<>();
        roles.spliterator().forEachRemaining(role -> {
            rolesList.add(role);
            subject.getPrincipals().add(new AbstractLoginService.RolePrincipal(role));
        });

        this.request.setAuthentication(new ElytronUserAuthentication(this.request.getAuthType(),
                new DefaultUserIdentity(subject, principal, rolesList.toArray(new String[rolesList.size()])),
                securityIdentity));
    }

    @Override
    public void authenticationFailed(String message, String mechanismName) {
    }

    @Override
    public void badRequest(HttpAuthenticationException error, String mechanismName) {
    }

    @Override
    public String getRequestMethod() {
        return this.request.getMethod();
    }

    @Override
    public URI getRequestURI() {
        try {
            return request.getHttpURI().toURI();
        } catch (URISyntaxException e) {
            return null;
        }
    }

    @Override
    public String getRequestPath() {
        return request.getHttpURI().getPath();
    }

    @Override
    public Map<String, List<String>> getRequestParameters() {
        Map<String, String[]> requestParameters = request.getParameterMap();
        if (requestParameters == null) {
            return null;
        }
        Map<String, List<String>> convertedRequestParameters = new HashMap<>(requestParameters.size());
        for (String parameter : requestParameters.keySet()) {
            convertedRequestParameters.put(parameter, Arrays.asList(requestParameters.get(parameter)));
        }
        return convertedRequestParameters;
    }

    @Override
    public List<HttpServerCookie> getCookies() {
        List<HttpServerCookie> cookies = Stream.of(this.request.getCookies()).map(new Function<javax.servlet.http.Cookie, HttpServerCookie>() {
            @Override
            public HttpServerCookie apply(javax.servlet.http.Cookie cookie) {
                return new HttpServerCookie() {
                    @Override
                    public String getName() {
                        return cookie.getName();
                    }

                    @Override
                    public String getValue() {
                        return cookie.getValue();
                    }

                    @Override
                    public String getDomain() {
                        return cookie.getDomain();
                    }

                    @Override
                    public int getMaxAge() {
                        return cookie.getMaxAge();
                    }

                    @Override
                    public String getPath() {
                        return cookie.getPath();
                    }

                    @Override
                    public boolean isSecure() {
                        return cookie.getSecure();
                    }

                    @Override
                    public int getVersion() {
                        return cookie.getVersion();
                    }

                    @Override
                    public boolean isHttpOnly() {
                        return cookie.isHttpOnly();
                    }
                };
            }
        }).collect(Collectors.toList());

        return cookies;
    }

    @Override
    public InputStream getRequestInputStream() {
        try {
            return request.getInputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public OutputStream getResponseOutputStream() {
        try {
            return response.getOutputStream();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public InetSocketAddress getSourceAddress() {
        return this.request.getRemoteInetSocketAddress();
    }

    @Override
    public void setResponseCookie(HttpServerCookie cookie) {
        this.response.addCookie(new HttpCookie(cookie.getName(), cookie.getValue(), cookie.getDomain(), cookie.getPath(), cookie.getMaxAge(), cookie.isHttpOnly(), cookie.isSecure(), null, cookie.getVersion()));
    }

    @Override
    public HttpScope getScope(Scope scope) {
        return null; // TODO
    }

    @Override
    public Collection<String> getScopeIds(Scope scope) {
        return null; // TODO
    }

    @Override
    public HttpScope getScope(Scope scope, String id) {
        return null; // TODO
    }

    class ElytronUserAuthentication extends UserAuthentication {
        private final SecurityIdentity securityIdentity;

        public ElytronUserAuthentication(String method, UserIdentity userIdentity, SecurityIdentity securityIdentity) {
            super(method, userIdentity);
            this.securityIdentity = securityIdentity;
        }

        public SecurityIdentity getSecurityIdentity() {
            return securityIdentity;
        }
    }

    private static void addPrivateCredentials(final Subject subject, final SecurityIdentity securityIdentity) {
        for (Credential credential : securityIdentity.getPrivateCredentials()) {
            if (credential instanceof PasswordCredential) {
                addPrivateCredential(subject, credential.castAs(PasswordCredential.class).getPassword());
            }
            else if (credential instanceof SecretKeyCredential) {
                addPrivateCredential(subject, credential.castAs(SecretKeyCredential.class).getSecretKey());
            }
            else if (credential instanceof KeyPairCredential) {
                addPrivateCredential(subject, credential.castAs(KeyPairCredential.class).getKeyPair());
            }
            else if (credential instanceof X509CertificateChainPrivateCredential) {
                addPrivateCredential(subject, credential.castAs(X509CertificateChainPrivateCredential.class).getCertificateChain());
            }
            else {
                addPrivateCredential(subject, credential);
            }
        }
    }

    private static void addPrivateCredential(final Subject subject, final Object credential) {
        subject.getPrivateCredentials().add(credential);
    }
}
