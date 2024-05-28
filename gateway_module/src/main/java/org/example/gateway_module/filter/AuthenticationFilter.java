package org.example.gateway_module.filter;

import org.example.gateway_module.config.Carousel;
import org.example.gateway_module.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.*;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.util.List;


@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

	private JwtUtils jwtUtils;
	private RestTemplate restTemplate;
	private RouteValidator routeValidator;
	@Value("${spring.profiles.active}")
	private String activeProfile;
	private Carousel carousel;

	public AuthenticationFilter(JwtUtils jwtUtils, RestTemplate restTemplate, RouteValidator routeValidator, Carousel carousel) {
		super(Config.class);
		this.jwtUtils = jwtUtils;
		this.restTemplate = restTemplate;
		this.routeValidator = routeValidator;
		this.carousel = carousel;
	}

	@Override
	public GatewayFilter apply(AuthenticationFilter.Config config) {
		return ((exchange, chain) -> {
			if (routeValidator.isSecure.test((ServerHttpRequest) exchange.getRequest())) {
				if (!exchange.getRequest().getCookies().containsKey(HttpHeaders.AUTHORIZATION) && !exchange.getRequest().getCookies().containsKey("refresh")) {
					exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
					exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

					StringBuilder stringBuilder = new StringBuilder("{\n")
							.append("\"timestamp\": \"")
							.append(new Timestamp(System.currentTimeMillis()))
							.append("\",\n")
							.append("\"message\": \"Wskazany token jest pusty lub nie ważny\",\n")
							.append("\"code\": \"A3\"\n")
							.append("}");

					return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
							                                                  .bufferFactory()
							                                                  .wrap((stringBuilder.toString()).getBytes())));
				}

				HttpCookie authCookie = exchange.getRequest().getCookies().get(HttpHeaders.AUTHORIZATION).get(0);
				HttpCookie refreshCookie = exchange.getRequest().getCookies().get("refresh").get(0);
				try {
					if (activeProfile.equals("test")) {
						jwtUtils.validateToken(authCookie.getValue());
					} else {
						String cookies = new StringBuilder()
								.append(authCookie.getName())
								.append("=")
								.append(authCookie.getValue())
								.append(";")
								.append(refreshCookie.getName())
								.append("=")
								.append(refreshCookie.getValue()).toString();

						HttpHeaders httpHeaders = new HttpHeaders();
						httpHeaders.add("Cookie", cookies);
						HttpEntity<Object> entity = new HttpEntity<>(httpHeaders);
						ResponseEntity<String> response = restTemplate.exchange("http://" + carousel.getUriAuth() + "/api/v1/auth/validate", HttpMethod.GET, entity, String.class);

						if (response.getStatusCode() == HttpStatus.OK) {
							List<String> cookiesList = response.getHeaders().get(HttpHeaders.SET_COOKIE);
							if (cookiesList != null) {
								List<java.net.HttpCookie> httpCookie = java.net.HttpCookie.parse(cookiesList.get(0));
								for (java.net.HttpCookie cookie : httpCookie) {
									exchange.getResponse().getCookies().add(
											cookie.getName(),
											ResponseCookie.from(cookie.getName(), cookie.getValue())
													.domain(cookie.getDomain())
													.path(cookie.getPath())
													.maxAge(cookie.getMaxAge())
													.secure(cookie.getSecure())
													.httpOnly(cookie.isHttpOnly())
													.build()
									);
								}
							}
						}
					}
				} catch (Exception e) {
					exchange.getResponse().writeWith(Flux.just(new DefaultDataBufferFactory().wrap(e.getMessage().getBytes())));
				}
			}
			return chain.filter(exchange);
		});
	}


	public static class Config {

	}


}
