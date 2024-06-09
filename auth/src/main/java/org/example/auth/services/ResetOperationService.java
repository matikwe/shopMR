package org.example.auth.services;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.auth.entity.ResetOperations;
import org.example.auth.entity.User;
import org.example.auth.repository.ResetOperationsRepository;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.sql.Timestamp;
import java.util.List;

@Service
@RequiredArgsConstructor
@EnableScheduling
@Slf4j
public class ResetOperationService {

	private final ResetOperationsRepository resetOperationsRepository;


	@Transactional
	public ResetOperations initResetOperation(User user) {
		log.info("--START initResetOperation");
		ResetOperations resetOperations = new ResetOperations();

		resetOperations.setUuid(user.getUuid());
		resetOperations.setCreateDate(new Timestamp(System.currentTimeMillis()));
		resetOperations.setUser(user);

		resetOperationsRepository.deleteAllByUser(user);
		log.info("--STOP initResetOperation");
		return resetOperationsRepository.saveAndFlush(resetOperations);
	}


	public void endOperation(String uuid) {
		resetOperationsRepository.findByUuid(uuid).ifPresent(resetOperationsRepository::delete);
	}

	@Scheduled(cron = "0 0/1 * * * *")
	protected void deleteExpireOperation() {
		List<ResetOperations> resetOperations = resetOperationsRepository.findExpiredOperations();
		if (resetOperations != null && !resetOperations.isEmpty()) {
			resetOperationsRepository.deleteAll(resetOperations);
		}
	}

}

