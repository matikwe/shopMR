package org.example.auth.configuration;

import lombok.RequiredArgsConstructor;
import org.example.auth.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor

public class UserConfiguration {

	private final UserRepository userRepository;

	@Bean
	public UserDetailsService userDetailsService() {
		return new CustomUserDetailsService(userRepository);
	}

	private static final String[] AUTH_WHITELIST = {
			"/api/v1/auth/register",
			"/api/v1/auth/login",
			"/api/v1/auth/validate",
			"/api/v1/auth/reset-password",
			"/api/v1/auth/activate",
			"/api/v1/auth/logout",
			"/api/v1/auth/auto-login",
			"/api/v1/auth/logged-in",
			"/api/v1/auth/authorize"
	};

	//https://stackoverflow.com/questions/74447778/spring-security-in-spring-boot-3
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(AUTH_WHITELIST).permitAll()
						.anyRequest().authenticated()
				)
				.build();
	}

	@Bean
	public AuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
		authenticationProvider.setUserDetailsService(userDetailsService());
		authenticationProvider.setPasswordEncoder(passwordEncoder());
		return authenticationProvider;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}


	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}