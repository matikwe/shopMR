package org.example.auth.services;

import com.google.common.base.Charsets;
import com.google.common.io.Files;
import lombok.RequiredArgsConstructor;
import org.example.auth.configuration.EmailConfiguration;
import org.example.auth.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import java.io.IOException;


@Service
@RequiredArgsConstructor
public class EmailService {

	private final EmailConfiguration emailConfiguration;

	@Value("${front.url}")
	private String fontendUrl;

	@Value("classpath:static/mail-activate.html")
	Resource activeTemplate;
	@Value("classpath:static/reset-password.html")
	private Resource recoveryTemplate;


	public void sendActivation(User user) {
		try {
			String html = Files.toString(activeTemplate.getFile(), Charsets.UTF_8);
			html = html.replace("https://google.com", fontendUrl + "/aktywuj/" + user.getUuid());
			emailConfiguration.sendMail(user.getEmail(), html, "Aktywacja konta", true);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public void sendPasswordRecovery(User user, String uuid) {
		try {
			String html = Files.toString(activeTemplate.getFile(), Charsets.UTF_8);
			html = html.replace("https://google.com", fontendUrl + "/odzyskaj-haslo/" + uuid);
			emailConfiguration.sendMail(user.getEmail(), html, "Odzyskaj hasło", true);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
