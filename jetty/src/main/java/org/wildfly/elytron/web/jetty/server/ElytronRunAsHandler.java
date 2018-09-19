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

import java.io.IOException;
import java.util.concurrent.Callable;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.HandlerWrapper;
import org.wildfly.common.Assert;
import org.wildfly.elytron.web.jetty.server.ElytronHttpExchange.ElytronUserAuthentication;
import org.wildfly.security.auth.server.SecurityIdentity;

/**
 * A {@link HandlerWrapper} to be placed after the request has switched to blocking mode to associate the
 * {@link SecurityIdentity} with the current thread.
 *
 * @author <a href="mailto:fjuma@redhat.com">Farah Juma</a>
 */
public class ElytronRunAsHandler extends HandlerWrapper {

    /**
     * Construct a new instance.
     *
     * @param handler the delegate handler
     */
    public ElytronRunAsHandler(Handler handler) {
        Assert.checkNotNullParam("handler", handler);
        super.setHandler(handler);
    }

    @Override
    public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        Authentication authentication = baseRequest.getAuthentication();
        SecurityIdentity securityIdentity = (authentication instanceof ElytronUserAuthentication) ? ((ElytronUserAuthentication) authentication).getSecurityIdentity() : null;
        if (securityIdentity != null) {
            try {
                securityIdentity.runAs((Callable<Void>) () -> {
                    super.handle(target, baseRequest, request, response);
                    return null;
                });
            } catch (Exception e) {
                throw new ServletException(e);
            }
        } else {
            super.handle(target,baseRequest,request,response);
        }
    }
}
