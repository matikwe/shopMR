package org.example.auth.services;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.example.auth.entity.*;
import org.example.auth.exceptions.UserDontExistException;
import org.example.auth.exceptions.UserExistingWithEmail;
import org.example.auth.exceptions.UserExistingWithName;
import org.example.auth.repository.ResetOperationsRepository;
import org.example.auth.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Arrays;

@Service
@RequiredArgsConstructor
public class UserService {

	private static final Logger log = LoggerFactory.getLogger(UserService.class);
	private final UserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
	private final ResetOperationService resetOperationService;
	private final ResetOperationsRepository operationsRepository;
	private final JwtService jwtService;
	private final AuthenticationManager authenticationManager;
	private final CookieService cookieService;
	private final EmailService emailService;
	private final ResetOperationsRepository resetOperationsRepository;
	@Value("${jwt.exp}")
	private int exp;
	@Value("${jwt.refresh.exp}")
	private int refreshExp;

	public void register(UserRegisterDTO userRegisterDTO) throws UserExistingWithName, UserExistingWithEmail {
		userRepository.findUserByLogin(userRegisterDTO.getLogin()).ifPresent(value -> {
			throw new UserExistingWithName("Użytkowanik o nazwie już istnieje");
		});
		userRepository.findUserByEmail(userRegisterDTO.getEmail()).ifPresent(value -> {
			throw new UserExistingWithEmail("Użytkownik z podanym mailem istnieje");
		});
		User user = buildUserEntity(userRegisterDTO);
		saveUser(user);
		emailService.sendActivation(user);
	}

	private User buildUserEntity(UserRegisterDTO userRegisterDTO) {
		User user = new User();
		user.setLock(true);
		user.setLogin(userRegisterDTO.getLogin());
		user.setPassword(userRegisterDTO.getPassword());
		user.setEmail(userRegisterDTO.getEmail());
		user.setEnabled(true);
		user.setRole(userRegisterDTO.getRole() != null ? userRegisterDTO.getRole() : Role.USER);
		return user;
	}

	public ResponseEntity<?> login(HttpServletResponse response, User authRequest) {
		User user = userRepository.findUserByLogin(authRequest.getUsername()).orElse(null);
		if (user != null) {
			Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
			if (authentication.isAuthenticated()) {
				Cookie refresh = cookieService.generateCookie("refresh", generateToken(authRequest.getUsername(), refreshExp), refreshExp);
				Cookie cookie = cookieService.generateCookie("Authorization", generateToken(authRequest.getUsername(), exp), exp);
				response.addCookie(cookie);
				response.addCookie(refresh);
				return ResponseEntity.ok(UserRegisterDTO.builder().login(user.getUsername()).email(user.getEmail()).role(user.getRole()).build());
			} else {
				ResponseEntity.ok(new AuthResponse(Code.A1));
			}
		}
		return ResponseEntity.ok(new AuthResponse(Code.A2));
	}

	private User saveUser(User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepository.saveAndFlush(user);
	}

	public String generateToken(String username, int exp) {
		return jwtService.generateToken(username, exp);
	}

	public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
		log.info("Clear all cookies");
		Cookie cookie = cookieService.removeCookie(request.getCookies(), "refresh");
		if (cookie != null) {
			response.addCookie(cookie);
		}
		return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
	}


	public void validateToken(HttpServletRequest request, HttpServletResponse response) throws ExpiredJwtException, IllegalArgumentException {
		String token = null;
		String refresh = null;
		if (request.getCookies() != null) {
			for (Cookie value : Arrays.stream(request.getCookies()).toList()) {
				if (value.getName().equals("Authorization")) {
					token = value.getValue();
				} else if (value.getName().equals("refresh")) {
					refresh = value.getValue();
				}
			}
		} else {
			throw new IllegalArgumentException("Token can't be null");
		}
		try {
			jwtService.validateToken(token);
		} catch (ExpiredJwtException | IllegalArgumentException e) {
			jwtService.validateToken(refresh);
			Cookie refreshCookie = cookieService.generateCookie("refresh", jwtService.refreshToken(refresh, refreshExp), refreshExp);
			Cookie cookie = cookieService.generateCookie("Authorization", jwtService.refreshToken(refresh, exp), exp);
			response.addCookie(cookie);
			response.addCookie(refreshCookie);
		}
	}

	public ResponseEntity<?> loginByToken(HttpServletRequest request, HttpServletResponse response) {
		try {
			validateToken(request, response);
			String refresh = null;
			for (Cookie value : Arrays.stream(request.getCookies()).toList()) {
				if (value.getName().equals("refresh")) {
					refresh = value.getValue();
				}
			}
			String login = jwtService.getSubject(refresh);
			User user = userRepository.findUserByLoginAndLockAndEnabled(login).orElse(null);
			if (user != null) {
				return ResponseEntity.ok(UserRegisterDTO.builder().login(user.getUsername()).email(user.getEmail()).role(user.getRole()).build());

			}
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthResponse(Code.A1));
		} catch (ExpiredJwtException | IllegalArgumentException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new AuthResponse(Code.A3));
		} catch (SignatureException e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new AuthResponse(Code.INVALID_JWT));
		}
	}

	public ResponseEntity<?> loggedIn(HttpServletRequest request, HttpServletResponse response) {
		try {
			validateToken(request, response);
			return ResponseEntity.ok(new LoginResponse(true));
		} catch (ExpiredJwtException | IllegalArgumentException e) {
			return ResponseEntity.ok(new LoginResponse(false));
		}
	}

	public void activateUser(String uuid) {
		User user = userRepository.findUserByUuid(uuid).orElse(null);
		if (user != null) {
			user.setLock(false);
			userRepository.save(user);
			return;
		}
		throw new UserDontExistException("User dont exist");
	}

	public void recoveryPassword(String email) {
		User user = userRepository.findUserByEmail(email).orElse(null);
		if (user != null) {
			ResetOperations resetOperations = resetOperationService.initResetOperation(user);
			emailService.sendPasswordRecovery(user, resetOperations.getUuid());
			return;
		}
		throw new UserDontExistException("User dont exist");
	}

	@Transactional
	public void resetPassword(ChangePasswordData changePasswordData) throws UserDontExistException {
		ResetOperations resetOperations = resetOperationsRepository.findByUuid(changePasswordData.getUuid()).orElse(null);
		if (resetOperations != null) {
			User user = userRepository.findUserByUuid(resetOperations.getUuid()).orElse(null);
			if (user != null) {
				user.setPassword(changePasswordData.getPassword());
				saveUser(user);
				resetOperationService.endOperation(resetOperations.getUuid());
				return;
			}
		}
		throw new UserDontExistException("User dont exist");
	}
}
