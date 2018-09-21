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

import org.eclipse.jetty.security.Authenticator;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.wildfly.security.auth.server.HttpAuthenticationFactory;
import org.wildfly.security.auth.server.MechanismConfigurationSelector;
import org.wildfly.security.auth.server.SecurityDomain;
import org.wildfly.security.http.HttpAuthenticationException;
import org.wildfly.security.http.HttpAuthenticator;
import org.wildfly.security.http.HttpServerAuthenticationMechanismFactory;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import java.util.stream.Collectors;

/**
 * Implementation of {@link Authenticator} for integration with Jetty.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ElytronAuthenticator implements Authenticator {

    private final SecurityDomain securityDomain;
    private HttpAuthenticationFactory httpAuthenticationFactory;

    private ElytronAuthenticator(final Builder builder) {
        this.securityDomain = builder.securityDomain;
        this.httpAuthenticationFactory = HttpAuthenticationFactory.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismConfigurationSelector(builder.mechanismConfigurationSelector)
                .setFactory(builder.httpServerAuthenticationMechanismFactory)
                .build();
    }

    @Override
    public void setConfiguration(AuthConfiguration configuration) {
        // no-op
    }

    @Override
    public String getAuthMethod() {
        return null;
    }

    @Override
    public void prepareRequest(ServletRequest request) {
        // no-op
    }

    @Override
    public Authentication validateRequest(ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory) throws ServerAuthException {
        Request request = (Request) servletRequest;
        Response response = (Response) servletResponse;
        HttpAuthenticator authenticator = HttpAuthenticator.builder()
                .setSecurityDomain(securityDomain)
                .setMechanismSupplier(() -> httpAuthenticationFactory.getMechanismNames().stream()
                        .map(mechanismName -> {
                            try {
                                return httpAuthenticationFactory.createMechanism(mechanismName);
                            } catch (HttpAuthenticationException e) {
                                throw new RuntimeException("Failed to create mechanism.", e);
                            }
                        })
                        .filter(m -> m != null)
                        .collect(Collectors.toList()))
                .setHttpExchangeSpi(new ElytronHttpExchange(request, response))
                .setRequired(mandatory)
                .build();

        boolean authenticated;
        try {
            authenticated = authenticator.authenticate();
        } catch (HttpAuthenticationException e) {
            throw new ServerAuthException(e);
        }
        if (authenticated) {
            return request.getAuthentication();
        } else {
            return Authentication.SEND_CONTINUE;
        }
    }

    @Override
    public boolean secureResponse(ServletRequest request, ServletResponse response, boolean mandatory, Authentication.User validatedUser) throws ServerAuthException {
        return true;
    }

    /**
     * Construct and return a new {@code Builder} to configure and create an instance of {@code ElytronAuthenticator}.
     *
     * @return a new {@code Builder} to configure and create an instance of {@code ElytronAuthenticator}.
     */
    public static Builder builder() {
        return new Builder();
    }


    /**
     * A {@code Builder} to configure and create an instance of {@code ElytronAuthenticator}.
     */
    public static final class Builder {

        private SecurityDomain securityDomain;
        private MechanismConfigurationSelector mechanismConfigurationSelector;
        private HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory;

        /**
         * Construct a new instance.
         */
        Builder() {
        }

        public Builder setSecurityDomain(final SecurityDomain securityDomain) {
            this.securityDomain = securityDomain;
            return this;
        }

        public Builder setMechanismConfigurationSelector(final MechanismConfigurationSelector mechanismConfigurationSelector) {
            this.mechanismConfigurationSelector = mechanismConfigurationSelector;
            return this;
        }

        public Builder setFactory(final HttpServerAuthenticationMechanismFactory httpServerAuthenticationMechanismFactory) {
            this.httpServerAuthenticationMechanismFactory = httpServerAuthenticationMechanismFactory;
            return this;
        }

        public ElytronAuthenticator build() {
            return new ElytronAuthenticator(this);
        }
    }
}
