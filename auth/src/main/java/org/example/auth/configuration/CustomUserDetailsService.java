package org.example.auth.configuration;

import lombok.RequiredArgsConstructor;
import org.example.auth.entity.User;
import org.example.auth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> user = userRepository.findUserByLogin(username);
		return user.map(CustomUserDetails::new)
				.orElseThrow(() -> new UsernameNotFoundException("User not found with name: " + username));
	}
}