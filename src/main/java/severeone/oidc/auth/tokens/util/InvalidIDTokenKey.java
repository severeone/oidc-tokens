package severeone.oidc.auth.tokens.util;

/**
 * Invalid ID Token key exception.
 */
public class InvalidIDTokenKey extends Exception {

	/**
	 * Creates a new Invalid ID Token key exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public InvalidIDTokenKey(final String message) {
		super(message);
	}

	/**
	 * Creates a new Invalid ID Token key exception with the specified message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public InvalidIDTokenKey(final String message, final Throwable cause) {
		super(message, cause);
	}
}
