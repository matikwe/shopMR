package org.example.auth.repository;

import org.example.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

	Optional<User> findUserByLogin(String login);

	@Query(nativeQuery = true, value = "SELECT * FROM users where login=?1 and is_lock=false and is_enabled=true")
	Optional<User> findUserByLoginAndLockAndEnabled(String login);

	@Query(nativeQuery = true, value = "SELECT * FROM users where login=?1 and is_lock=false and is_enabled=true and role='ADMIN'")
	Optional<User> findUserByLoginAndLockAndEnabledAndIsAdmin(String login);

	Optional<User> findUserByEmail(String email);

	Optional<User> findUserByUuid(String uuid);

}
