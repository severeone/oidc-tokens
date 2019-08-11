package co.kernelnetworks.oidc.auth.tokens;

import co.kernelnetworks.oidc.auth.tokens.gen.AccessTokenKeyGenerator;
import co.kernelnetworks.oidc.auth.tokens.gen.IDTokenKeyGenerator;
import co.kernelnetworks.oidc.auth.tokens.gen.UUIDTokenGenerator;
import co.kernelnetworks.oidc.auth.tokens.util.CaseMedicalResearchSecurityContext;
import co.kernelnetworks.oidc.auth.tokens.util.InvalidAccessToken;
import co.kernelnetworks.oidc.auth.tokens.util.InvalidAccessTokenKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;

import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;

import static com.shazam.shazamcrest.MatcherAssert.assertThat;
import static com.shazam.shazamcrest.matcher.Matchers.sameBeanAs;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumingThat;

@DisplayName("Access Token")
class AccessTokenTest {

    @Test
    @DisplayName("Having proper default claim list")
    void havingProperClaimList() {
        assertEquals(new HashSet<String>(JWTClaimsSet.getRegisteredNames()) {{
                         remove("nbf");
                         remove("jti");
                         add("azp");
                         add("scope");
                         add("rtoken");
                     }}, AccessToken.getClaimNames()
        );
    }

    @Test
    @DisplayName("Creating new AccessToken.Builder")
    void creatingNewBuilder() {
        new AccessToken.Builder();
    }

    @Nested
    @DisplayName("Building by Builder")
    class BuildingByBuilder {

        AccessToken.Builder builder;

        @BeforeEach
        void createBuilder() {
            builder = new AccessToken.Builder();
        }

        @Test
        @DisplayName("with no user-set claims")
        void withNoUserSetClaims() {
            AccessToken accessToken = builder.build();
            verifyToken(accessToken, (at) -> {
                verifyTokenValidation(at, null, false);
            });
        }

        @Test
        @DisplayName("with user ID")
        void withUserID() {
            final String userId = "12345";
            AccessToken accessToken = builder
                    .userId(userId)
                    .build();
            verifyToken(accessToken, (at) -> {
                assertEquals(userId, at.getUserId(), "user ID");
                verifyTokenValidation(at, null, false);
            });
        }

        @Test
        @DisplayName("with client ID")
        void withClientID() {
            final String clientId = "client-id";
            AccessToken accessToken = builder
                    .clientId(clientId)
                    .build();
            verifyToken(accessToken, (at) -> {
                assertEquals(clientId, at.getClientId(), "client ID");
                verifyTokenValidation(at, clientId, false);
            });
        }

        @ParameterizedTest(name = "lifetime = {0} seconds")
        @CsvSource({
                "0, false",
                "5, true",
                "10000, false"
        })
        @DisplayName("with token lifetime")
        void withLifetime(int lifetime, boolean expiredAfter60) {
            AccessToken accessToken = builder
                    .lifeTime(lifetime)
                    .build();

            verifyTokenValidation(accessToken, null, false);
            try {
                Thread.sleep(6 * 1000);
            } catch (InterruptedException e) {
                fail("Failed to sleep: " + e.getMessage());
            }
            verifyTokenValidation(accessToken, null, expiredAfter60);

            AccessToken decrypted = verifyEncryption(accessToken);
            verifyDefaultClaims(decrypted);
            verifyTokenValidation(accessToken, null, expiredAfter60);
        }

        @ParameterizedTest(name = "\"{0}\"")
        @ValueSource(strings = {"", "openid", "profile", "profile picture", "profile picture openid phone"})
        @DisplayName("with custom scope values")
        void withCustomScopeValues(String scope) {
            List<String> scopeValues = Arrays.asList(scope.split(" "));
            Set<String> expectedScopeValues = new HashSet<>();
            for (String s : scopeValues) {
                builder.addScope(s);
                expectedScopeValues.add(s);
                verifyScopeValues(expectedScopeValues);
            }

            for (String s : scopeValues) {
                builder.removeScope(s);
                expectedScopeValues.remove(s);
                verifyScopeValues(expectedScopeValues);
            }

            builder.addScope(scopeValues);
            expectedScopeValues.addAll(scopeValues);
            verifyScopeValues(expectedScopeValues);
        }

        @ParameterizedTest(name = "{1}, \"{2}\"")
        @ArgumentsSource(CustomClaimsProvider.class)
        @DisplayName("with custom claims")
        void withCustomClaims(Class<?> classT, String name, Object value, boolean assertBean) {
            verifyCustomClaim(classT, value, assertBean);
        }

        <T> void verifyCustomClaim(Class<T> classT, Object value, boolean assertBean) {
            final String name = "custom-claim-" +  classT.getName();

            AccessToken accessToken = builder
                    .claim(name, value)
                    .build();

            verifyToken(accessToken, (at) -> {
                verifyTokenValidation(at, null, false);
                try {
                    final T actualObject = at.getClaim(classT, name);
                    assertAll(classT.getSimpleName() + " claim",
                            () -> assertNotNull(actualObject),
                            () -> {
                                if (!assertBean)
                                    assertEquals(value, actualObject);
                            },
                            () -> {
                                if (assertBean)
                                    assertThat(actualObject, sameBeanAs(value));
                            }
                    );
                } catch (ParseException e) {
                    fail("Failed to parse claim: " + e.getMessage());
                }
            });
        }

        void verifyScopeValues(Set<String> expectedScopeValues) {
            AccessToken accessToken = builder.build();

            verifyToken(accessToken, (at) -> {
                verifyTokenValidation(at, null, false);

                List<String> actualScope = at.getScope();
                assertNotNull(actualScope, "scope not present");
                for (String s : expectedScopeValues)
                    assumingThat(!s.isEmpty(),
                            () -> assertTrue(actualScope.contains(s), String.format("no \"%s\"", s))
                    );
            });
        }

        void verifyDefaultClaims(AccessToken accessToken) {
            assertNotNull(accessToken, "Access Token is null");
            assertAll("default claims",
                    () -> {
                        String issuer = accessToken.getIssuer();
                        assertNotNull(issuer, "issuer not present");
                        Assertions.assertEquals(CaseMedicalResearchSecurityContext.ISSUER, issuer,
                                "issuer is wrong");
                    },
                    () -> {
                        List<String> audience = accessToken.getAudience();
                        assertNotNull(audience, "audience not present");

                        assertAll("audience",
                                () -> assertEquals(2, accessToken.getAudience().size(),
                                        "not exactly two"),
                                () -> assertTrue(audience.contains(
                                        CaseMedicalResearchSecurityContext.API_ENDPOINT),
                                        "no Case API endpoint"),
                                () -> assertTrue(audience.contains(
                                        CaseMedicalResearchSecurityContext.USER_INFO_ENDPOINT),
                                        "no Case UserInfo endpoint")
                        );
                    },
                    () -> {
                        List<String> scope = accessToken.getScope();
                        assertNotNull(scope, "scope not present");
                        assertTrue(scope.contains("openid"), "doesn't have openid");
                    },
                    () -> {
                        String refreshToken = accessToken.getRefreshToken();
                        assertNotNull(refreshToken, "Refresh Token not present");
                        Assertions.assertTrue(UUIDTokenGenerator.checkFormat(refreshToken),
                                "Refresh Token has invalid format");
                    },
                    () -> {
                        Date issuedAt = accessToken.getIssuedAt();
                        Date expiresAt = accessToken.getExpiresAt();
                        assertNotNull(issuedAt, "issued at not present");
                        assertNotNull(expiresAt, "expires at not present");
                        Instant now = Instant.now();
                        assertTrue(!issuedAt.toInstant().isAfter(now),
                                String.format("issued at (%tT) is after now (%tT)",
                                        issuedAt, new Date(now.toEpochMilli())));
                        assertTrue(!expiresAt.before(issuedAt),
                                String.format("issued at (%tT) is after expires at (%tT)",
                                        issuedAt, expiresAt));
                    }
            );
        }

        void verifyTokenValidation(AccessToken accessToken, String clientId, boolean expired) {
            assertNotNull(accessToken);
            assertAll("Access Token validation",
                    () -> assertTrue(accessToken.issuerIsValid(), "invalid issuer"),
                    () -> assertTrue(accessToken.clientIsValid(clientId), "invalid client ID"),
                    () -> assertTrue(accessToken.refreshTokenIsValid(), "invalid Refresh Token"),
                    () -> assertEquals(expired, accessToken.isExpired(), String.format(
                            "invalid expiration (issued at = %tT, expires at = %tT, now = %tT)",
                            accessToken.getIssuedAt(), accessToken.getExpiresAt(), Date.from(Instant.now()))),
                    () -> assertEquals(!expired, accessToken.isValid(clientId), "invalid token")
            );
        }

        AccessToken verifyEncryption(AccessToken accessToken) {
            Supplier<String> generator = () -> {
                String token = null;
                try {
                    token = AccessTokenKeyGenerator.generate();
                } catch (NoSuchAlgorithmException e) {
                    fail("This should never ever happen: " + e.getMessage());
                }
                return token;
            };

            final String actualKey = generator.get();
            final String wrongKey = generator.get();
            final String emptyKey = "";

            String idTokenKey = null;
            try {
                idTokenKey = IDTokenKeyGenerator.generate().toString();
            } catch (JOSEException e) {
                fail("Failed to generate ID Token key");
            }
            final String invalidKey = idTokenKey;

            String encrypted = null;
            try {
                encrypted = accessToken.encryptToString(actualKey);
            } catch (InvalidAccessTokenKey | InvalidAccessToken e) {
                fail("Failed to encrypt the Access Token: " + e.getMessage());
            }
            assertNotNull(encrypted);

            assertThrows(InvalidAccessTokenKey.class, () -> {
                accessToken.encryptToString(invalidKey);
            }, "encryption with an invalid key");
            assertThrows(InvalidAccessTokenKey.class, () -> {
                accessToken.encryptToString(emptyKey);
            }, "encryption with an empty key");

            final String enc = encrypted;
            assertThrows(InvalidAccessToken.class, () -> {
                AccessToken.decryptFromString(enc, wrongKey);
            }, "decryption with a wrong key");
            assertThrows(InvalidAccessTokenKey.class, () -> {
                AccessToken.decryptFromString(enc, invalidKey);
            }, "decryption with an invalid key");
            assertThrows(InvalidAccessTokenKey.class, () -> {
                AccessToken.decryptFromString(enc, emptyKey);
            }, "decryption with an empty key");
            assertThrows(InvalidAccessToken.class, () -> {
                AccessToken.decryptFromString("", actualKey);
            }, "decryption of an empty token");
            assertThrows(InvalidAccessToken.class, () -> {
                AccessToken.decryptFromString(enc + UUID.randomUUID(), actualKey);
            }, "decryption of an invalid token");

            AccessToken decrypted = null;
            try {
                decrypted = AccessToken.decryptFromString(enc, actualKey);
            } catch (InvalidAccessToken | InvalidAccessTokenKey e) {
                fail("Failed to decrypt the Access Token from a string: " + e.getMessage());
            }
            return decrypted;
        }

        void verifyToken(AccessToken accessToken, AdditionalVerification additionalVerification) {
            verifyDefaultClaims(accessToken);
            additionalVerification.verify(accessToken);
            AccessToken decrypted = verifyEncryption(accessToken);
            verifyDefaultClaims(decrypted);
            additionalVerification.verify(decrypted);
        }
    }

    interface AdditionalVerification {
        void verify(AccessToken accessToken);
    }
}