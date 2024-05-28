package org.example.auth.exceptions;

public class UserExistingWithName extends RuntimeException{

	public UserExistingWithName(String message, Throwable cause) {
		super(message, cause);
	}

	public UserExistingWithName(String message) {
		super(message);
	}

	public UserExistingWithName(Throwable cause) {
		super(cause);
	}
}
