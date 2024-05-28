package org.example.gateway_module.filter;

import org.springframework.http.server.ServerHttpRequest;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.function.Predicate;

@Component
public class RouteValidator {

	public static final List<String> openApiPoints = List.of("/auth/register", "/auth/login", "/auth/validate", "/auth/activate", "/auth/reset-password");

	public Predicate<ServerHttpRequest> isSecure = serverHttpRequest -> openApiPoints.stream().noneMatch(uri -> serverHttpRequest.getURI().getPath().contains(uri));
}
