package severeone.oidc.auth.tokens;

import severeone.oidc.auth.tokens.gen.AccessTokenKeyGenerator;
import severeone.oidc.auth.tokens.gen.UUIDTokenGenerator;
import severeone.oidc.auth.tokens.util.SevereoneSecurityContext;
import severeone.oidc.auth.tokens.util.InvalidAccessToken;
import severeone.oidc.auth.tokens.util.InvalidAccessTokenKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.*;

import net.minidev.json.JSONObject;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

/**
 * OpenID Connect Access Token. This class is thread-safe.
 *
 * <p>Supports the following {@link #getClaimNames()} claims:
 *
 * <ul>
 *     <li>iss - Issuer
 *     <li>sub - Subject
 *     <li>aud - Audience
 *     <li>azp - Authorized Party
 *     <li>iat - Issued At
 *     <li>exp - Expiration Time
 *     <li>scope - Scope
 *     <li>rtoken - Refresh Token
 * </ul>
 *
 * <p>The set may also contain custom claims; these will be serialised and
 * parsed along the registered ones.
 *
 * <p>Example Access Token:
 *
 * <pre>
 * {
 *   "sub"                        : "12345",
 *   "exp"                        : 1300819380,
 *   "nonce"                      : "HJKseydsu2d"
 * }
 * </pre>
 *
 * <p>Example usage:
 *
 * <pre>
 * // Create a new Access Token.
 * AccessToken accessToken = new AccessToken.Builder()
 *     .userId(12345)
 *     .clientId("client-id")
 *     .lifeTime(10000)
 *     .claim("nonce", "HJd878sdfh")
 *     .build();

 * // Generate a new AES key to encrypt the Access Token.
 * String key = AccessTokenKeyGenerator.generate();
 *
 * // Encrypt the Access Token and serialize it to a string.
 * String accessTokenString = accessToken.encryptToString(key);
 *
 * // Read an Access Token from a string using a local key.
 * accessToken = AccessToken.readFromString(accessTokenString, key);
 *
 * // Validate the Access Token.
 * assertTrue(accessToken.isValid("client-id"));
 *
 * // Extract a Refresh Token from it.
 * String refreshToken = accessToken.getRefreshToken();
 * </pre>
 */
public final class AccessToken {

	private static final String AUTHORIZED_PARTY_CLAIM = "azp";
	private static final String SCOPE_CLAIM = "scope";
	private static final String REFRESH_TOKEN = "rtoken";

	private static final String NOT_BEFORE_CLAIM = "nbf";
	private static final String JWT_ID_CLAIM = "jti";

	private static final JWEAlgorithm ENCRYPTION_ALGORITHM = JWEAlgorithm.DIR;
	private static final EncryptionMethod ENCRYPTION_METHOD = EncryptionMethod.A128CBC_HS256;

	private static final Set<String> STANDARD_CLAIM_NAMES;

	static {
		Set<String> n = new HashSet<>(JWTClaimsSet.getRegisteredNames());

		n.remove(NOT_BEFORE_CLAIM);
		n.remove(JWT_ID_CLAIM);
		n.add(AUTHORIZED_PARTY_CLAIM);
		n.add(SCOPE_CLAIM);
		n.add(REFRESH_TOKEN);

		STANDARD_CLAIM_NAMES = Collections.unmodifiableSet(n);
	}

	/**
	 * Builder for constructing Access Tokens.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
	 * AccessToken accessToken = new AccessToken.Builder()
	 *     .userId(12345)
	 *     .clientId("client-id")
	 *     .lifeTime(10000)
	 *     .claim("nonce", "HJd878sdfh")
	 *     .build();
	 * </pre>
	 */
	public static class Builder {

		private static final String OPENID_SCOPE = "openid";

		/**
		 * The JWT Claims Set Builder
		 */
		private final JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder()
				.issuer(SevereoneSecurityContext.ISSUER)
				.audience(new ArrayList<String>(){{
					add(SevereoneSecurityContext.API_ENDPOINT);
					add(SevereoneSecurityContext.USER_INFO_ENDPOINT);
				}});

        /**
         * The Scope values
         */
        private final List<String> scopeValues = new ArrayList<String>(){{ add(OPENID_SCOPE); }};

        /**
         * The Access Token lifetime
         */
        private long lifetimeSeconds;

        /**
		 * Creates a new builder.
		 */
		public Builder() {
		}

		/**
		 * Sets the User ID which will be used as ({@code aud}) claim.
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
		 * Sets the Client ID which will be used as ({@code azp}) claim.
		 *
		 * @param clientId The Client ID, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder clientId(final String clientId) {
			this.jwtClaimsSetBuilder.claim(AUTHORIZED_PARTY_CLAIM, clientId);
			return this;
		}

		/**
		 * Sets the Access Token life time which will be used to set ({@code exp}) claim.
		 *
		 * @param lifeTimeSeconds The Access Token life time, {@code 0} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder lifeTime(final long lifeTimeSeconds) {
			this.lifetimeSeconds = lifeTimeSeconds;
			return this;
		}

		/**
		 * Adds the scope value to the scope ({@code scope}) claim.
		 *
		 * @param scopeValue The scope value, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder addScope(final String scopeValue) {
			if (scopeValue != null && !scopeValue.isEmpty())
				this.scopeValues.add(scopeValue);
			return this;
		}

		/**
		 * Adds the scope values to the scope ({@code scope}) claim.
		 *
		 * @param scopeValues The scope values, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder addScope(final List<String> scopeValues) {
			for (String sv: scopeValues)
				if (sv != null && !sv.isEmpty())
					this.scopeValues.add(sv);
			return this;
		}

        /**
         * Removes the scope value from the scope ({@code scope}) claim.
         *
         * @param scopeValue The scope value, {@code null} if not specified.
         *
         * @return This builder.
         */
        public Builder removeScope(final String scopeValue) {
            if (scopeValue != null)
                this.scopeValues.remove(scopeValue);
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
		    if (!AccessToken.STANDARD_CLAIM_NAMES.contains(name))
			    this.jwtClaimsSetBuilder.claim(name, value);
			return this;
		}

		/**
		 * Builds a new Access Token.
		 *
		 * @return The Access Token.
		 */
		public AccessToken build() {
		    Instant issued = Instant.now();
			JWTClaimsSet claimsSet = jwtClaimsSetBuilder
                    .claim(SCOPE_CLAIM, scopeValues)
                    .claim(REFRESH_TOKEN, UUIDTokenGenerator.generate())
                    .issueTime(Date.from(issued))
                    .expirationTime(Date.from(issued.plusSeconds(lifetimeSeconds)))
                    .build();
			return new AccessToken(claimsSet);
		}
	}

	/**
	 * The Access Token claim set.
	 */
	private final JWTClaimsSet claims;

	/**
	 * Creates a new Access Token.
	 *
	 * @param claims The JWT claims set. Must not be {@code null}.
	 */
	private AccessToken(final JWTClaimsSet claims) {
		this.claims = claims;
	}

	/**
	 * Encrypts this Access Token with the specified key to a string.
	 *
	 * @param key The Access Token key. Must not be {@code null}.
	 *
	 * @return The encrypted Access Token in a compact JOSE form.
	 *
	 * @throws InvalidAccessTokenKey If cannot the specified key has a wrong format.
	 * @throws InvalidAccessToken If this Access Token cannot be encrypted.
	 */
	public String encryptToString(final String key) throws InvalidAccessTokenKey, InvalidAccessToken {
		EncryptedJWT jwt = new EncryptedJWT(new JWEHeader(ENCRYPTION_ALGORITHM, ENCRYPTION_METHOD), claims);
		SecretKey secretKey = secretKeyFromString(key);
		JWEEncrypter encrypter;
		try {
			encrypter = new DirectEncrypter(secretKey);
		} catch (KeyLengthException e) {
			throw new InvalidAccessTokenKey("Failed to create JWE encrypter: " + e.getMessage());
		}
		try {
			jwt.encrypt(encrypter);
		} catch (JOSEException e) {
			throw new InvalidAccessToken("Access Token cannot be encrypted: " + e.getMessage());
		}
		return jwt.serialize();
    }

	/**
	 * Decrypts this Access Token from the string in a compact form with the specified key.
	 *
	 * @param s The Access Token in a compact JOSE form. Must not be {@code null}.
	 * @param key The Access Token key. Must not be {@code null}.
	 *
	 * @throws InvalidAccessToken If cannot parse the specified string or cannot decrypt it
	 *                            with the specified key.
	 * @throws InvalidAccessTokenKey If cannot the specified key has a wrong format.
	 *
	 * @return A new Access Token.
	 */
	public static AccessToken decryptFromString(final String s, final String key)
			throws InvalidAccessToken, InvalidAccessTokenKey {
		ConfigurableJWTProcessor<SevereoneSecurityContext> jwtProcessor =
				new DefaultJWTProcessor<>();
		JWKSource<SevereoneSecurityContext> jweKeySource = new ImmutableSecret<>(secretKeyFromString(key));
		JWEKeySelector<SevereoneSecurityContext> jweKeySelector = new JWEDecryptionKeySelector<>(
				ENCRYPTION_ALGORITHM, ENCRYPTION_METHOD, jweKeySource);
		jwtProcessor.setJWEKeySelector(jweKeySelector);

		// We don't want to verify claims on this step.
		jwtProcessor.setJWTClaimsSetVerifier((claimsSet, context) -> {});

		JWTClaimsSet claims;
		try {
			claims = jwtProcessor.process(s, null);
		} catch (ParseException e) {
			throw new InvalidAccessToken("Failed to parse an access token from string.");
		} catch (BadJOSEException|JOSEException e) {
			throw new InvalidAccessToken("Failed to decrypt an access token with the specified key.", e);
		}

		return new AccessToken(claims);
	}

	/**
	 * Validates the Access Token by checking its issuer, expiration time and client ID.
	 *
	 * @return {@code true} if the Access Token is valid, {@code false} otherwise.
	 */
	public boolean isValid(final String clientId) {
		return issuerIsValid() && clientIsValid(clientId) && !isExpired() && refreshTokenIsValid();
	}

	/**
	 * Checks if the Access Token has expired.
	 *
	 * @return {@code true} if the Access Token has expired, {@code false} otherwise.
	 */
	public boolean isExpired() {
		final Date now = new Date();
		final Date exp = claims.getExpirationTime();
		final Date iat = claims.getIssueTime();
		// Expiration and issue time is not supposed to be null because we set it by Builder
		return !iat.equals(exp) && exp.before(now);
	}

	/**
	 * Checks if the issuer of the Access Token is valid.
	 *
	 * @return {@code true} if the issuer is valid, {@code false} otherwise.
	 */
	public boolean issuerIsValid() {
		return SevereoneSecurityContext.ISSUER.equals(claims.getIssuer());
	}

	/**
	 * Checks if the Client for which the Access Token was issued is valid.
	 *
	 * @param clientId The Client ID.
	 *
	 * @return {@code true} if the Client is valid, {@code false} otherwise.
	 */
	public boolean clientIsValid(final String clientId) {
		Object azp = claims.getClaim(AUTHORIZED_PARTY_CLAIM);
		return (clientId == null && azp == null) || (clientId != null && clientId.equals(azp));
	}

	/**
	 * Checks if the Refresh Token specified in the Access Token is valid.
	 *
	 * @return {@code true} if the Refresh Token is valid, {@code false} otherwise.
	 */
	public boolean refreshTokenIsValid() {
		String rt = getRefreshToken();
		return rt != null && UUIDTokenGenerator.checkFormat(rt);
	}

	/**
	 * Extracts the issuer of the Access Token, if it's set and has a valid format
	 *
	 * @return The issuer name if it's set and has a valid format, {@code null} otherwise.
	 */
	public String getIssuer() {
		return claims.getIssuer();
	}

	/**
	 * Extracts the user ID for whom the Access Token was issued, if it's set and has a valid format.
	 *
	 * @return The user ID, if it's set and has a valid format, {@code null} otherwise.
	 */
	public String getUserId() {
		return claims.getSubject();
	}

	/**
	 * Extracts the audience of the Access Token, if it's set and has a valid format
	 *
	 * @return The audience list if it's set and has a valid format, {@code null} otherwise.
	 */
	public List<String> getAudience() {
		return claims.getAudience();
	}

	/**
	 * Extracts the Client ID for which the Access Token was issued, if it's set and has a valid format
	 *
	 * @return The Client ID if it's set and has a valid format, {@code null} otherwise.
	 */
	public String getClientId() {
		String azp;
		try {
			azp = claims.getStringClaim(AUTHORIZED_PARTY_CLAIM);
		} catch (ParseException e) {
			return null;
		}
		return azp;
	}

	/**
	 * Extracts the time and date when the Access Token was issued, if it's set and has a valid format
	 *
	 * @return The issuance time and date if it's set and has a valid format, {@code null} otherwise.
	 */
	public Date getIssuedAt() {
		return claims.getIssueTime();
	}

	/**
	 * Extracts the time and date when the Access Token expires, if it's set and has a valid format
	 *
	 * @return The expiration time and date if it's set and has a valid format, {@code null} otherwise.
	 */
	public Date getExpiresAt() {
		return claims.getExpirationTime();
	}

	/**
	 * Extracts scope of the Access Token, if it's set and has a valid format
	 *
	 * @return The scope values list if it's set and has a valid format, {@code null} otherwise.
	 */
	public List<String> getScope() {
		List<String> scope;
		try {
			scope = claims.getStringListClaim(SCOPE_CLAIM);
		} catch (ParseException e) {
			return null;
		}
		return scope;
	}

	/**
	 * Extracts the Refresh Token associated with the Access Token, if it's set and has a valid format
	 *
	 * @return The Refresh Token if it's set and has a valid format, {@code null} otherwise.
	 */
	public String getRefreshToken() {
		String rt;
		try {
			rt = claims.getStringClaim(REFRESH_TOKEN);
		} catch (ParseException e) {
			return null;
		}
		return rt;
	}

	/**
	 * Extracts a custom claim from the Access Token, if it's set and has a valid format.
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
	 * Returns the standard Access Token claim names.
	 *
	 * @return The standard claim names.
	 */
	public static Set<String> getClaimNames() {
		return STANDARD_CLAIM_NAMES;
	}

	/**
	 * Creates an Access Token encryption key from the string value.
	 *
	 * @param key The Access Token key. Must not be {@code null}.
	 *
	 * @return An Access Token key.
	 *
	 * @throws InvalidAccessTokenKey If cannot the specified key has a wrong format.
	 */
	private static SecretKey secretKeyFromString(final String key) throws InvalidAccessTokenKey {
		if (!AccessTokenKeyGenerator.checkFormat(key))
			throw new InvalidAccessTokenKey("Wrong format of the Access Token key");
		byte[] decodedKey = Base64.getDecoder().decode(key);
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, AccessTokenKeyGenerator.ALGORITHM_NAME);
	}
}
