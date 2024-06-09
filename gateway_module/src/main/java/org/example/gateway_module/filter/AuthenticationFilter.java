package org.example.gateway_module.filter;

import lombok.extern.slf4j.Slf4j;
import org.example.gateway_module.config.Carousel;
import org.example.gateway_module.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.sql.Timestamp;
import java.util.List;

@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

	private final RouteValidator validator;
	private final RestTemplate template;
	private final JwtUtils jwtUtils;
	@Value("${spring.profiles.active}")
	private String activeProfile;
	private Carousel carousel;
	private HttpCookie authCookie;
	private HttpCookie refreshCookie;
	private ServerWebExchange exchange;

	public AuthenticationFilter(JwtUtils jwtUtils, RestTemplate restTemplate, RouteValidator validator, Carousel carousel) {
		super(Config.class);
		this.carousel = carousel;
		this.jwtUtils = jwtUtils;
		this.template = restTemplate;
		this.validator = validator;
	}

	@Override
	public GatewayFilter apply(Config config) {
		return ((exchange, chain) -> {
			this.exchange = exchange;
			log.info("--START GatewayFilter");
			if (validator.isSecure.test(exchange.getRequest())) {
				if (!exchange.getRequest().getCookies().containsKey(HttpHeaders.AUTHORIZATION) && !exchange.getRequest().getCookies().containsKey("refresh")) {
					exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
					exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
					return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap((errorCodeA3()).getBytes())));
				}
				List<HttpCookie> authCookies = exchange.getRequest().getCookies().get(HttpHeaders.AUTHORIZATION);
				List<HttpCookie> refreshCookies = exchange.getRequest().getCookies().get("refresh");
				if (authCookies != null) {
					authCookie = authCookies.get(0);
					if (refreshCookies != null) {
						refreshCookie = refreshCookies.get(0);
						log.info("--START validate Token");
						try {
							if (activeProfile.equals("test")) {
								log.debug("Init self auth methods (only for tests)");
								jwtUtils.validateToken(authCookie.getValue());
							} else {
								initHttp();
							}
						} catch (HttpClientErrorException e) {
							handleHttpClientErrorException(e);
						}
					}
				}
			}
			log.info("--STOP validate Token");
			log.info("--STOP GatewayFilter");
			return chain.filter(exchange);
		});
	}

	private String errorCodeA3() {
		return new StringBuilder()
				.append("{\n")
				.append("\"timestamp\": \"")
				.append(new Timestamp(System.currentTimeMillis()))
				.append("\",\n")
				.append("\"message\": \"Wskazany token jest pusty lub nie ważny\",\n")
				.append("\"code\": \"A3\"\n")
				.append("}")
				.toString();
	}

	private String getCookies() {
		return new StringBuilder().append(authCookie.getName())
				.append("=")
				.append(authCookie.getValue())
				.append(";")
				.append(refreshCookie.getName())
				.append("=")
				.append(refreshCookie.getValue())
				.toString();
	}

	private void initHttp() {
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add("Cookie", getCookies());
		HttpEntity<Object> entity = new HttpEntity<>(httpHeaders);
		ResponseEntity<String> response = template.exchange("http://" + carousel.getUriAuth() + "/api/v1/auth/validate", HttpMethod.GET, entity, String.class);
		successLogin(response);
	}

	private void handleHttpClientErrorException(HttpClientErrorException e) {
		log.warn("Can't login bad token");
		String message = e.getMessage().substring(7);
		message = message.substring(0, message.length() - 1);
		ServerHttpResponse response = exchange.getResponse();
		HttpHeaders headers = response.getHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		response.setStatusCode(HttpStatus.UNAUTHORIZED);
		exchange.getResponse().writeWith(Flux.just(new DefaultDataBufferFactory().wrap(message.getBytes())));
	}

	private void successLogin(ResponseEntity<String> response) {
		if (response.getStatusCode() == HttpStatus.OK) {
			List<String> cookiesList = response.getHeaders().get(HttpHeaders.SET_COOKIE);
			if (cookiesList != null) {
				List<java.net.HttpCookie> httpCookie = java.net.HttpCookie.parse(cookiesList.get(0));
				for (java.net.HttpCookie cookie : httpCookie) {
					addCookieToResponse(cookie);
				}
			}
			log.info("Successful login");
		}
	}

	private void addCookieToResponse(java.net.HttpCookie cookie) {
		exchange.getResponse().getCookies().add(cookie.getName(), ResponseCookie.from(cookie.getName(), cookie.getValue())
				.domain(cookie.getDomain())
				.path(cookie.getPath())
				.maxAge(cookie.getMaxAge())
				.secure(cookie.getSecure())
				.httpOnly(cookie.isHttpOnly())
				.build());
	}

	public static class Config {

	}
}