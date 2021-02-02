package severeone.oidc.auth.tokens.gen;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

import java.text.ParseException;
import java.util.UUID;

/**
 * OpenID Connect ID Token Key Generator.
 *
 * <p>Generates RSA keys for ID Tokens signing.
 */
public class IDTokenKeyGenerator {

	/**
	 * The RSA key size, in bits.
	 */
	public static final int RSA_KEY_SIZE = 2048;

	/**
	 * The Signing algorithm.
	 */
	public static final JWSAlgorithm ALGORITHM = JWSAlgorithm.RS256;

	/**
	 * Generates a key for ID Token signing.
	 *
	 * @return An ID Token key.
	 */
	public static RSAKey generate() throws JOSEException {
		return new RSAKeyGenerator(RSA_KEY_SIZE)
				.keyUse(KeyUse.SIGNATURE)
				.algorithm(ALGORITHM)
				.keyID(UUID.randomUUID().toString())
				.generate();
	}

	/**
	 * Parse the given string to create a RSA JSON key.
	 *
	 * @param key A string to parse.
	 *
	 * @return RSA key if it can be parsed from the given string, {@code null} otherwise.
	 */
	public static RSAKey parse(final String key) {
        RSAKey rsaKey;
		try {
			rsaKey = RSAKey.parse(key);
		} catch (ParseException e) {
			return null;
		}
		return rsaKey;
	}
}
