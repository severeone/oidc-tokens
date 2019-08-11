package co.kernelnetworks.oidc.auth.tokens.util;

/**
 * Invalid Access Token key exception.
 */
public class InvalidAccessTokenKey extends Exception {

	/**
	 * Creates a new Invalid Access Token key exception with the specified message.
	 *
	 * @param message The exception message.
	 */
	public InvalidAccessTokenKey(final String message) {
		super(message);
	}
}