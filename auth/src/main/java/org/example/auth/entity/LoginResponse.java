package org.example.auth.entity;

import lombok.Getter;
import lombok.Setter;

import java.sql.Timestamp;

@Getter
@Setter
public class LoginResponse {

	private final String timestamp;
	private final boolean massage;
	private final Code code;

	public LoginResponse(boolean message) {
		this.timestamp = String.valueOf(new Timestamp(System.currentTimeMillis()));
		this.massage = message;
		this.code = Code.SUCCESS;
	}
}