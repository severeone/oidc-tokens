package severeone.oidc.auth.tokens.util;

/**
 * Invalid ID Token exception.
 */
public class InvalidIDToken extends Exception {

	/**
	 * Creates a new Invalid ID Token exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public InvalidIDToken(final String message) {
		super(message);
	}

	/**
	 * Creates a new Invalid ID Token exception with the specified message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public InvalidIDToken(final String message, final Throwable cause) {
		super(message, cause);
	}
}
