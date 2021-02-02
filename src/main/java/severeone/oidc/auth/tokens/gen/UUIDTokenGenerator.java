package severeone.oidc.auth.tokens.gen;

import java.util.UUID;

/**
 * UUID Token Generator.
 *
 * <p>Generates random UUID values.
 */
public class UUIDTokenGenerator {

	/**
	 * Generates a new UUID token.
	 *
	 * @return A new token as a string.
	 */
	public static String generate() {
		return UUID.randomUUID().toString();
	}

	/**
	 * Checks if the given string has the UUID format.
	 *
	 * @param token A string to check.
	 *
	 * @return {@code true} if the string has the UUID format, {@code false} otherwise.
	 */
	public static boolean checkFormat(final String token) {
		try {
			UUID.fromString(token);
		} catch (Exception e) {
			return false;
		}
		return true;
	}

}
