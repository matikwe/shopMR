package org.example.auth.fasada;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.example.auth.entity.*;
import org.example.auth.exceptions.UserDontExistException;
import org.example.auth.exceptions.UserExistingWithEmail;
import org.example.auth.exceptions.UserExistingWithName;
import org.example.auth.services.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

	private static final Logger log = LoggerFactory.getLogger(AuthController.class);
	private final UserService userService;

	@PostMapping("/register")
	public ResponseEntity<?> addNewUser(@Valid @RequestBody UserRegisterDTO userRegisterDTO) {
		try {
			userService.register(userRegisterDTO);
			return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
		} catch (UserExistingWithName e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new AuthResponse(Code.A4));
		} catch (UserExistingWithEmail e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new AuthResponse(Code.A5));
		}
	}

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody User user, HttpServletResponse response) {
		return userService.login(response, user);
	}

	@GetMapping("/auto-login")
	public ResponseEntity<?> autoLogin(HttpServletResponse response, HttpServletRequest request) {
		return userService.loginByToken(request, response);
	}

	@GetMapping("/logged-in")
	public ResponseEntity<?> loggedIn(HttpServletResponse response, HttpServletRequest request) {
		return userService.loggedIn(request, response);
	}

	@GetMapping("/logout")
	public ResponseEntity<?> logout(HttpServletResponse response, HttpServletRequest request) {
		return userService.logout(request, response);
	}


	@GetMapping("/validate")
	public ResponseEntity<AuthResponse> validateToken(HttpServletRequest request, HttpServletResponse response) {
		try {
			userService.validateToken(request, response);
			return ResponseEntity.ok(new AuthResponse(Code.PERMIT));
		} catch (IllegalArgumentException | ExpiredJwtException e) {
			return ResponseEntity.status(401).body(new AuthResponse(Code.A3));
		}
	}

	@GetMapping("/activate")
	public ResponseEntity<AuthResponse> activateUser(@RequestParam String uuid) {
		try {
			userService.activateUser(uuid);
			return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
		} catch (UserDontExistException e) {
			return ResponseEntity.status(400).body(new AuthResponse(Code.A6));
		}
	}

	@PostMapping("/reset-password")
	public ResponseEntity<AuthResponse> sendMailRecovery(@RequestBody ResetPasswordData resetPasswordData) {
		try {
			log.info("--START sendMailRecovery");
			userService.recoveryPassword(resetPasswordData.getEmail());
			log.info("--STOP sendMailRecovery");
			return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
		} catch (UserDontExistException e) {
			log.info("User dont exist in database");
			return ResponseEntity.status(400).body(new AuthResponse(Code.A6));
		}
	}

	@PatchMapping("/reset-password")
	public ResponseEntity<AuthResponse> recoveryMail(@RequestBody ChangePasswordData changePasswordData) {
		try {
			log.info("--START recoveryMail");
			userService.resetPassword(changePasswordData);
			log.info("--STOP recoveryMail");
			return ResponseEntity.ok(new AuthResponse(Code.SUCCESS));
		} catch (UserDontExistException e) {
			log.info("User dont exist in database");
			return ResponseEntity.status(400).body(new AuthResponse(Code.A6));
		}
	}

	@ResponseStatus(HttpStatus.BAD_REQUEST)
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ValidationMessage handleValidationException(MethodArgumentNotValidException ex) {
		return new ValidationMessage(ex.getBindingResult().getAllErrors().get(0).getDefaultMessage());
	}
}