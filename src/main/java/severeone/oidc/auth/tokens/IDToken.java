package severeone.oidc.auth.tokens;

import severeone.oidc.auth.tokens.gen.IDTokenKeyGenerator;
import severeone.oidc.auth.tokens.util.SevereoneSecurityContext;
import severeone.oidc.auth.tokens.util.InvalidIDToken;
import severeone.oidc.auth.tokens.util.InvalidIDTokenKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import net.minidev.json.JSONObject;

import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

/**
 * OpenID Connect ID Token. This class is thread-safe.
 *
 * <p>Supports the following {@link #getClaimNames()} claims:
 *
 * <ul>
 *     <li>iss - Issuer
 *     <li>sub - Subject
 *     <li>aud - Audience
 *     <li>exp - Expiration Time
 *     <li>iat - Issued At
 *     <li>nonce - Nonce
 * </ul>
 *
 * <p>The set may also contain custom claims; these will be serialised and
 * parsed along the registered ones.
 *
 * <p>Example ID Token:
 *
 * <pre>
 * {
 *   "iss"                        : "severeone.xyz",
 *   "sub"                        : "12345",
 *   "aud"                        : "client_id",
 *   "exp"                        : 1300819380,
 *   "iat"                        : 1300712330,
 *   "nonce"                      : "HJKseydsu2d"
 * }
 * </pre>
 *
 * <p>Example usage:
 *
 * <pre>
 * // Create a new ID Token.
 * IDToken idToken = new IDToken.Builder()
 *     .userId(12345)
 *     .clientId("client-id")
 *     .lifeTime(10000)
 *     .nonce("HJd878sdfh")
 *     .build();
 *
 * // Generate a new RSA key to sign the ID Token.
 * RSAKey key = IDTokenKeyGenerator.generate();
 *
 * // Sign the ID Token and serialize it to a string.
 * String idTokenString = idToken.signToString(key.toString());
 *
 * // Read an ID Token from a string using a local key.
 * idToken = IDToken.readFromString(idTokenString, key.toString());
 *
 * // Read an ID Token from a string using a remote link.
 * idToken = IDToken.readFromString(idTokenString, new URL("https://example.com/jwk.json"));
 *
 * // Validate the ID Token.
 * assertTrue(idToken.isValid("client-id", "HJd878sdfh"));
 * </pre>
 */
public final class IDToken {

	private static final String NOT_BEFORE_CLAIM = "nbf";
	private static final String JWT_ID_CLAIM = "jti";

	private static final String NONCE_CLAIM = "nonce";

	private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.RS256;

	private static final Set<String> STANDARD_CLAIM_NAMES;

	static {
		Set<String> n = new HashSet<>(JWTClaimsSet.getRegisteredNames());

		n.add(NONCE_CLAIM);
		n.remove(NOT_BEFORE_CLAIM);
		n.remove(JWT_ID_CLAIM);

		STANDARD_CLAIM_NAMES = Collections.unmodifiableSet(n);
	}

	/**
	 * Builder for constructing ID Tokens.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
     * IDToken idToken = new IDToken.Builder()
     *     .userId(12345)
     *     .clientId("client-id")
     *     .lifeTime(10000)
     *     .nonce("HJd878sdfh")
     *     .build();
	 * </pre>
	 */
	public static class Builder {

		/**
		 * The JWT Claims Set Builder
		 */
		private final JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder()
				.issuer(SevereoneSecurityContext.ISSUER);

        /**
         * The ID Token lifetime
         */
        private long lifetimeSeconds;

        /**
		 * Creates a new builder.
		 */
		public Builder() {
		}

		/**
		 * Sets the User ID which will be used as ({@code sub}) claim.
		 *
		 * @param userId The User ID, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder userId(final String userId) {
			this.jwtClaimsSetBuilder.subject(userId);
			return this;
		}

		/**
		 * Sets the Client ID which will be used as ({@code aud}) claim.
		 *
		 * @param clientId The Client ID, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder clientId(final String clientId) {
			this.jwtClaimsSetBuilder.audience(clientId);
			return this;
		}

		/**
		 * Sets the ID Token life time which will be used to set ({@code exp}) claim.
		 *
		 * @param lifeTimeSeconds The ID Token life time, {@code 0} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder lifeTime(final long lifeTimeSeconds) {
			this.lifetimeSeconds = lifeTimeSeconds;
			return this;
		}

        /**
         * Sets the nonce associated with a Client session which will be used as ({@code nonce}) claim.
         *
         * @param nonce The nonce, {@code null} if not specified.
         *
         * @return This builder.
         */
        public Builder nonce(final String nonce) {
            this.jwtClaimsSetBuilder.claim(NONCE_CLAIM, nonce);
            return this;
        }

        /**
		 * Sets the specified claim (registered or custom).
		 *
		 * @param name  The name of the claim to set. Must not be
		 *              {@code null}.
		 * @param value The value of the claim to set, {@code null} if
		 *              not specified. Should map to a JSON entity.
		 *
		 * @return This builder.
		 */
		public Builder claim(final String name, final Object value) {
		    if (!IDToken.STANDARD_CLAIM_NAMES.contains(name))
			    this.jwtClaimsSetBuilder.claim(name, value);
			return this;
		}

		/**
		 * Builds a new ID Token.
		 *
		 * @return The ID Token.
		 */
		public IDToken build() {
		    Instant issued = Instant.now();
			JWTClaimsSet claimsSet = jwtClaimsSetBuilder
                    .issueTime(Date.from(issued))
                    .expirationTime(Date.from(issued.plusSeconds(lifetimeSeconds)))
                    .build();
			return new IDToken(claimsSet);
		}
	}

	/**
	 * The ID Token claim set.
	 */
	private final JWTClaimsSet claims;

	/**
	 * Creates a new ID Token.
	 *
	 * @param claims The JWT claims set. Must not be {@code null}.
	 */
	private IDToken(final JWTClaimsSet claims) {
		this.claims = claims;
	}

	/**
	 * Sign this ID Token with the specified key to a string.
	 *
     * @param key The ID Token key as a string. Must not be {@code null}.
	 *
	 * @return The signed ID Token in a compact JOSE form.
	 *
	 * @throws InvalidIDTokenKey If the specified key has a wrong format.
	 * @throws InvalidIDToken If this ID Token failed to be signed.
	 */
	public String signToString(final String key) throws InvalidIDTokenKey, InvalidIDToken {
	    RSAKey rsaJWK = IDTokenKeyGenerator.parse(key);
	    if (rsaJWK == null)
	        throw new InvalidIDTokenKey("Failed to parse ID Token key from a string.");

		// Create RSA-signer with the private key
        JWSSigner signer;
        try {
            signer = new RSASSASigner(rsaJWK);
        } catch (JOSEException e) {
            throw new InvalidIDTokenKey("Failed to create a signer using an ID Token key.");
        }

		// Prepare JWS object with simple string as payload
		SignedJWT jwt = new SignedJWT(
		        new JWSHeader.Builder(SIGNING_ALGORITHM).keyID(rsaJWK.getKeyID()).build(), claims);

		// Compute the RSA signature
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new InvalidIDToken("ID Token cannot be signed.", e);
        }

		return jwt.serialize();
	}

	/**
	 * Read an ID Token from the string in a compact form and verify its signature with the specified key.
	 *
	 * @param s The ID Token in a compact JOSE form. Must not be {@code null}.
	 * @param key The ID Token key as a string. Must not be {@code null}.
	 *
     * @throws InvalidIDTokenKey If the specified key has a wrong format.
     * @throws InvalidIDToken If cannot parse the specified string or failed to verify a signature of
     *                        an ID Token with the specified key.
	 *
	 * @return A new ID Token.
	 */
	public static IDToken readFromString(final String s, final String key)
            throws InvalidIDToken, InvalidIDTokenKey {
		JWK k;
		try {
            k = JWK.parse(key);
        } catch (ParseException e) {
		    throw new InvalidIDTokenKey("Failed to parse ID token key from a string.");
        }
		return readFromString(s, new ImmutableJWKSet<>(new JWKSet(k)));
	}

    /**
     * Read an ID Token from the string in a compact form and verify its signature with keys from
     * the given remote link.
     *
     * @param s The ID Token in a compact JOSE form. Must not be {@code null}.
     * @param remoteKeys The URL to a remote ID Token key set in JSON form. Must not be {@code null}.
     *
     * @throws InvalidIDTokenKey If the specified key has a wrong format.
     * @throws InvalidIDToken If cannot parse the specified string or failed to verify a signature of
     *                        an ID Token with the specified key.
     *
     * @return A new ID Token.
     */
	public static IDToken readFromString(final String s, final URL remoteKeys)
			throws InvalidIDToken, InvalidIDTokenKey {
		return readFromString(s, new RemoteJWKSet<>(remoteKeys));
	}
    /**
     * Read an ID Token from the string in a compact form and verify its signature with keys from
     * the given key source.
     *
     * @param s The ID Token in a compact JOSE form. Must not be {@code null}.
     * @param keySource The ID Token key source. Must not be {@code null}.
     *
     * @throws InvalidIDTokenKey If the specified key has a wrong format.
     * @throws InvalidIDToken If cannot parse the specified string or failed to verify a signature of
     *                        an ID Token with the specified key.
     *
     * @return A new ID Token.
     */
    private static IDToken readFromString(final String s,
                                          JWKSource<SevereoneSecurityContext> keySource)
        throws InvalidIDToken, InvalidIDTokenKey {
        ConfigurableJWTProcessor<SevereoneSecurityContext> jwtProcessor =
                new DefaultJWTProcessor<>();

        JWSKeySelector<SevereoneSecurityContext> keySelector =
                new JWSVerificationKeySelector<>(SIGNING_ALGORITHM, keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        // We don't want to verify claims on this step.
        jwtProcessor.setJWTClaimsSetVerifier((claimsSet, context) -> {});

        JWTClaimsSet claims;
        try {
            claims = jwtProcessor.process(s, null);
        } catch (ParseException e) {
            throw new InvalidIDToken(
                    "Failed to parse an ID token from string.", e);
        } catch (BadJOSEException|JOSEException e) {
            throw new InvalidIDToken(
                    "Failed to verify a signature of an ID token with the specified key.", e);
        }

        return new IDToken(claims);
    }

    /**
	 * Validates the ID Token by checking its issuer, expiration time, user ID and client ID.
	 *
	 * @return {@code true} if the ID Token is valid, {@code false} otherwise.
	 */
	public boolean isValid(final String clientId) {
		return issuerIsValid() && clientIsValid(clientId) && !isExpired() && getUserId() != null;
	}

    /**
     * Validates the ID Token by checking its issuer, expiration time, user ID, client ID and nonce.
     *
     * @return {@code true} if the ID Token is valid, {@code false} otherwise.
     */
    public boolean isValid(final String clientId, final String nonce) {
        return isValid(clientId) && nonceIsValid(nonce);
    }

	/**
	 * Checks if the ID Token has expired.
	 *
	 * @return {@code true} if the ID Token has expired, {@code false} otherwise.
	 */
	public boolean isExpired() {
		final Date now = new Date();
		final Date exp = claims.getExpirationTime();
		final Date iat = claims.getIssueTime();
		// Expiration and issue time is not supposed to be null because we set it by Builder
		return !iat.equals(exp) && exp.before(now);
	}

	/**
	 * Checks if the issuer of the ID Token is valid.
	 *
	 * @return {@code true} if the issuer is valid, {@code false} otherwise.
	 */
	public boolean issuerIsValid() {
		return claims.getIssuer().equals(SevereoneSecurityContext.ISSUER);
	}

	/**
	 * Checks if the Client for which the ID Token was issued is valid.
	 *
	 * @param clientId The Client ID. Must not be {@code null}.
	 *
	 * @return {@code true} if the Client is valid, {@code false} otherwise.
	 */
	public boolean clientIsValid(final String clientId) {
		if (getClientId() == null)
			return false;
		return clientId.equals(getClientId());
	}

    /**
     * Checks if the nonce associated with a prior Authentication Request is present in the ID Token.
     *
     * @param nonce The nonce. Must not be {@code null}.
     *
     * @return {@code true} if the nonce is valid, {@code false} otherwise.
     */
    public boolean nonceIsValid(final String nonce) {
        return claims.getClaim(NONCE_CLAIM).equals(nonce);
    }

    /**
	 * Extracts the issuer of the ID Token, if it's set and has a valid format
	 *
	 * @return The issuer name if it's set and has a valid format, {@code null} otherwise.
	 */
	public String getIssuer() {
		return claims.getIssuer();
	}

	/**
	 * Extracts the user ID for whom the ID Token was issued, if it's set and has a valid format.
	 *
	 * @return The user ID, if it's set and has a valid format, {@code null} otherwise.
	 */
	public String getUserId() {
		return claims.getSubject();
	}

	/**
	 * Extracts the Client ID for which the ID Token was issued, if it's set and has a valid format
	 *
	 * @return The Client ID if it's set and has a valid format, {@code null} otherwise.
	 */
	public String getClientId() {
		if (claims.getAudience().size() == 0)
			return null;
		return claims.getAudience().get(0);
	}

	/**
	 * Extracts the time and date when the ID Token was issued, if it's set and has a valid format
	 *
	 * @return The issuance time and date if it's set and has a valid format, {@code null} otherwise.
	 */
	public Date getIssuedAt() {
		return claims.getIssueTime();
	}

    /**
     * Extracts the nonce associated with the Client for which ID Token was issued, if it's set and has a valid format
     *
     * @return The nonce if it's set and has a valid format, {@code null} otherwise.
     */
    public String getNonce() {
        Object nonce = claims.getClaim(NONCE_CLAIM);
        if (nonce instanceof String)
            return (String)nonce;
        return null;
    }

	/**
	 * Extracts the time and date when the ID Token expires, if it's set and has a valid format
	 *
	 * @return The expiration time and date if it's set and has a valid format, {@code null} otherwise.
	 */
	public Date getExpiresAt() {
		return claims.getExpirationTime();
	}

	/**
	 * Extracts a custom claim from the ID Token, if it's set and has a valid format.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return A custom claim if it's set and has a valid format, {@code null} otherwise.
	 */
	@SuppressWarnings("unchecked")
	public <T> T getClaim(Class<T> classT, final String name) throws ParseException {
		if (classT.getName().equals(String.class.getName()))
			return (T)claims.getStringClaim(name);
		else if (classT.getName().equals(Integer.class.getName()))
			return (T)claims.getIntegerClaim(name);
		else if (classT.getName().equals(Long.class.getName()))
			return (T)claims.getLongClaim(name);
		else if (classT.getName().equals(Date.class.getName()))
			return (T)claims.getDateClaim(name);
		else if (classT.getName().equals(List.class.getName()))
			return (T)claims.getStringListClaim(name);
		else if (classT.getName().equals(Boolean.class.getName()))
			return (T)claims.getBooleanClaim(name);
		else if (classT.getName().equals(Float.class.getName()))
			return (T)claims.getFloatClaim(name);
		else if (classT.getName().equals(JSONObject.class.getName()))
			return (T)claims.getJSONObjectClaim(name);
		else
			return (T)claims.getClaim(name);
	}

	/**
	 * Returns the standard ID Token claim names.
	 *
	 * @return The standard claim names.
	 */
	public static Set<String> getClaimNames() {
		return STANDARD_CLAIM_NAMES;
	}
}
