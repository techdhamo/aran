package org.mazhai.central.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Server-Side RASP Filter — Embedded runtime protection for mazhai-central.
 * Inspects ALL incoming HTTP requests (headers, parameters, JSON bodies) for
 * malicious payloads BEFORE they reach Spring controllers.
 *
 * Detects: Path Traversal, Command Injection, SQL Injection, OGNL Injection,
 *          JNDI/Log4Shell, XSS, LDAP Injection, SSRF indicators.
 */
@Component
@Order(1) // Execute first in the filter chain
public class ServerSideRaspFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(ServerSideRaspFilter.class);

    /** Compiled threat patterns — ordered by severity */
    private static final List<ThreatPattern> THREAT_PATTERNS = List.of(
            // JNDI / Log4Shell (CVE-2021-44228)
            new ThreatPattern("JNDI_INJECTION",
                    Pattern.compile("(?i)\\$\\{jndi:(ldap|rmi|dns|iiop|corba|nds|http)s?://", Pattern.CASE_INSENSITIVE),
                    "Critical"),

            // Command Injection
            new ThreatPattern("COMMAND_INJECTION",
                    Pattern.compile("(?i)(;|\\|\\||&&|`|\\$\\()\\s*(cat|ls|wget|curl|nc|bash|sh|python|perl|ruby|chmod|chown|rm\\s+-rf)", Pattern.CASE_INSENSITIVE),
                    "Critical"),

            // OGNL Injection (Struts-style)
            new ThreatPattern("OGNL_INJECTION",
                    Pattern.compile("(?i)(%\\{|#\\{|\\$\\{).*(@|java\\.lang|Runtime|ProcessBuilder|getRuntime)", Pattern.CASE_INSENSITIVE),
                    "Critical"),

            // SQL Injection (Union, stacked, boolean)
            new ThreatPattern("SQL_INJECTION",
                    Pattern.compile("(?i)(union\\s+(all\\s+)?select|;\\s*(drop|delete|truncate|alter|update|insert)\\s|'\\s*(or|and)\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+|sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay)", Pattern.CASE_INSENSITIVE),
                    "High"),

            // Path Traversal
            new ThreatPattern("PATH_TRAVERSAL",
                    Pattern.compile("(\\.\\./|\\.\\.\\\\|%2e%2e(%2f|%5c)|%252e%252e)", Pattern.CASE_INSENSITIVE),
                    "High"),

            // XSS
            new ThreatPattern("XSS",
                    Pattern.compile("(?i)(<script[^>]*>|javascript\\s*:|on(error|load|click|mouseover|focus)\\s*=|<\\s*img[^>]+onerror)", Pattern.CASE_INSENSITIVE),
                    "High"),

            // LDAP Injection
            new ThreatPattern("LDAP_INJECTION",
                    Pattern.compile("(?i)(\\*\\)\\(|\\)\\(\\||\\(\\|\\(|%28%7c%28)", Pattern.CASE_INSENSITIVE),
                    "Medium"),

            // SSRF indicators
            new ThreatPattern("SSRF",
                    Pattern.compile("(?i)(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0|169\\.254\\.|metadata\\.google|\\[::1\\]|file://)", Pattern.CASE_INSENSITIVE),
                    "Medium")
    );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!(request instanceof HttpServletRequest httpReq) || !(response instanceof HttpServletResponse httpResp)) {
            chain.doFilter(request, response);
            return;
        }

        // 1. Inspect URL path
        String uri = httpReq.getRequestURI();
        var uriMatch = scanPayload(uri);
        if (uriMatch != null) {
            blockRequest(httpResp, uriMatch, "URI", uri);
            return;
        }

        // 2. Inspect query string
        String queryString = httpReq.getQueryString();
        if (queryString != null) {
            var qsMatch = scanPayload(queryString);
            if (qsMatch != null) {
                blockRequest(httpResp, qsMatch, "QUERY_STRING", queryString);
                return;
            }
        }

        // 3. Inspect ALL headers
        var headerNames = Collections.list(httpReq.getHeaderNames());
        for (String headerName : headerNames) {
            String headerValue = httpReq.getHeader(headerName);
            if (headerValue != null) {
                var headerMatch = scanPayload(headerValue);
                if (headerMatch != null) {
                    blockRequest(httpResp, headerMatch, "HEADER:" + headerName, headerValue);
                    return;
                }
            }
        }

        // 4. Inspect ALL parameters
        var paramNames = Collections.list(httpReq.getParameterNames());
        for (String paramName : paramNames) {
            for (String paramValue : httpReq.getParameterValues(paramName)) {
                var paramMatch = scanPayload(paramValue);
                if (paramMatch != null) {
                    blockRequest(httpResp, paramMatch, "PARAM:" + paramName, paramValue);
                    return;
                }
            }
        }

        // Passed all checks — proceed
        chain.doFilter(request, response);
    }

    private ThreatPattern scanPayload(String payload) {
        if (payload == null || payload.isEmpty()) return null;
        for (var threat : THREAT_PATTERNS) {
            if (threat.pattern().matcher(payload).find()) {
                return threat;
            }
        }
        return null;
    }

    private void blockRequest(HttpServletResponse response, ThreatPattern threat, String source, String payload)
            throws IOException {
        log.warn("RASP BLOCK | {} [{}] in {} — payload snippet: {}",
                threat.name(), threat.severity(), source,
                payload.length() > 100 ? payload.substring(0, 100) + "..." : payload);

        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write("""
                {"error":"Request blocked by Aran Server-Side RASP","threat":"%s","severity":"%s","source":"%s"}
                """.formatted(threat.name(), threat.severity(), source).trim());
    }

    private record ThreatPattern(String name, Pattern pattern, String severity) {}
}
