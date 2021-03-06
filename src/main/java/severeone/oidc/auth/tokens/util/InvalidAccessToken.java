package severeone.oidc.auth.tokens.util;

/**
 * Invalid Access Token exception.
 */
public class InvalidAccessToken extends Exception {

	/**
	 * Creates a new Invalid Access Token exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public InvalidAccessToken(final String message) {
		super(message);
	}

	/**
	 * Creates a new Invalid Access Token exception with the specified message and cause.
	 *
	 * @param message The exception message.
	 * @param cause   The exception cause.
	 */
	public InvalidAccessToken(final String message, final Throwable cause) {
		super(message, cause);
	}
}
