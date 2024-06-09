package org.example.auth.services;

import jakarta.servlet.http.Cookie;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CookieService {

	private final JwtService jwtService;

	public Cookie generateCookie(String name, String value, int exp) {
		Cookie cookie = new Cookie(name, value);
		cookie.setHttpOnly(true);
		cookie.setMaxAge(exp);
		return cookie;
	}

	public Cookie removeCookie(Cookie[] cookies, String name) {
		for (Cookie cookie : cookies) {
			if (cookie.getName().equals(name)) {
				return generateCookie(name, jwtService.refreshToken(cookie.getValue(), 0), 0);
			}
		}
		return null;
	}

}
