package org.example.auth.entity;

public enum Code {
	SUCCESS("Operacja zakończona sukcesen"),
	PERMIT("Przyznano dostep"),
	A1("Użytkownik o podanych danych nie istnieje lub nie aktywował konta"),
	A2("Użytkownik o wskazanej nazwie nie istnieje"),
	A3("Wskazany token jest pusty lub nie ważny"),
	A4("Użytkownik o podanej nazwie już istnieje"),
	A5("Użytkownik o podanym mailu już istnieje"),
	A6("Użytkownik nie istnieje"),
	INVALID_JWT("Invalid JWT signature");


	public final String label;

	Code(String label) {
		this.label = label;
	}
}
