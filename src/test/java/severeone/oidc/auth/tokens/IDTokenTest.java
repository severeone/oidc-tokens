package severeone.oidc.auth.tokens;

import severeone.oidc.auth.tokens.gen.AccessTokenKeyGenerator;
import severeone.oidc.auth.tokens.gen.IDTokenKeyGenerator;
import severeone.oidc.auth.tokens.util.SevereoneSecurityContext;
import severeone.oidc.auth.tokens.util.InvalidIDToken;
import severeone.oidc.auth.tokens.util.InvalidIDTokenKey;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;

import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;

import static com.shazam.shazamcrest.MatcherAssert.assertThat;
import static com.shazam.shazamcrest.matcher.Matchers.sameBeanAs;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ID Token")
class IDTokenTest {

    private static Thread remoteKeysServerThread;

    @BeforeAll
    static void startServerForRemoteKeysTest() {
        remoteKeysServerThread = new Thread(new RemoteKeysServer());
        remoteKeysServerThread.start();
    }

    @AfterAll
    static void stopServerForRemoteKeysTest() {
        remoteKeysServerThread.interrupt();
    }

    @Test
    @DisplayName("Having proper default claim list")
    void havingProperClaimList() {
        assertEquals(new HashSet<String>(JWTClaimsSet.getRegisteredNames()) {{
                         remove("nbf");
                         remove("jti");
                         add("nonce");
                     }}, IDToken.getClaimNames()
        );
    }

    @Test
    @DisplayName("Creating new IDToken.Builder")
    void creatingNewBuilder() {
        new IDToken.Builder();
    }

    @Nested
    @DisplayName("Building by Builder")
    class BuildingByBuilder {

        IDToken.Builder builder;

        @BeforeEach
        void createBuilder() {
            builder = new IDToken.Builder();
        }

        @Test
        @DisplayName("with no user-set claims")
        void withNoUserSetClaims() {
            IDToken idToken = builder.build();
            verifyToken(idToken, (at) -> {
                verifyTokenValidation(at, null, false, false, false,null);
            });
        }

        @Test
        @DisplayName("with user ID")
        void withUserID() {
            final String userId = "12345";
            IDToken idToken = builder
                    .userId(userId)
                    .build();
            verifyToken(idToken, (at) -> {
                assertEquals(userId, at.getUserId(), "user ID");
                verifyTokenValidation(at, null, false, false, true, null);
            });
        }

        @Test
        @DisplayName("with client ID")
        void withClientID() {
            final String clientId = "client-id";
            IDToken idToken = builder
                    .clientId(clientId)
                    .build();
            verifyToken(idToken, (at) -> {
                assertEquals(clientId, at.getClientId(), "client ID");
                verifyTokenValidation(at, clientId, false, true, false, null);
            });
        }

        @Test
        @DisplayName("with nonce")
        void withNonce() {
            final String nonce = "noncenoncenonce";
            final String clientId = "client-id";
            IDToken idToken = builder
                    .clientId(clientId)
                    .userId("12345")
                    .nonce(nonce)
                    .build();
            verifyToken(idToken, (at) -> {
                assertEquals(nonce, at.getNonce(), "nonce");
                verifyTokenValidation(at, clientId, false, true, true, nonce);
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
            final String clientId = "client-id";
            IDToken idToken = builder
                    .clientId(clientId)
                    .userId("12345")
                    .lifeTime(lifetime)
                    .build();

            verifyTokenValidation(idToken, clientId, false, true, true, null);
            try {
                Thread.sleep(6 * 1000);
            } catch (InterruptedException e) {
                fail("Failed to sleep: " + e.getMessage());
            }
            verifyTokenValidation(idToken, clientId, expiredAfter60, true, true, null);

            IDToken parsed = verifySigning(idToken);
            verifyDefaultClaims(parsed);
            verifyTokenValidation(idToken, clientId, expiredAfter60, true, true, null);
        }

        @ParameterizedTest(name = "{1}, \"{2}\"")
        @ArgumentsSource(CustomClaimsProvider.class)
        @DisplayName("with custom claims")
        void withCustomClaims(Class<?> classT, String name, Object value, boolean assertBean) {
            verifyCustomClaim(classT, value, assertBean);
        }

        <T> void verifyCustomClaim(Class<T> classT, Object value, boolean assertBean) {
            final String clientId = "client-id";
            final String name = "custom-claim-" +  classT.getName();

            IDToken idToken = builder
                    .clientId(clientId)
                    .userId("12345")
                    .claim(name, value)
                    .build();

            verifyToken(idToken, (at) -> {
                verifyTokenValidation(at, clientId, false, true, true, null);
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

        void verifyDefaultClaims(IDToken idToken) {
            assertNotNull(idToken, "ID Token is null");
            assertAll("default claims",
                    () -> {
                        String issuer = idToken.getIssuer();
                        assertNotNull(issuer, "issuer not present");
                        Assertions.assertEquals(SevereoneSecurityContext.ISSUER, issuer,
                                "issuer is wrong");
                    },
                    () -> {
                        Date issuedAt = idToken.getIssuedAt();
                        Date expiresAt = idToken.getExpiresAt();
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

        void verifyTokenValidation(IDToken idToken, String clientId, boolean expired,
                                   boolean clientSet, boolean userSet, String nonce) {
            assertNotNull(idToken);
            assertAll("ID Token validation",
                    () -> assertTrue(idToken.issuerIsValid(),
                            "invalid issuer"),
                    () -> assertEquals(clientSet, idToken.clientIsValid(clientId),
                            "invalid client ID"),
                    () -> assertEquals(userSet, idToken.getUserId() != null,
                            "invalid user ID"),
                    () -> assertEquals(expired, idToken.isExpired(), String.format(
                            "invalid expiration (issued at = %tT, expires at = %tT, now = %tT)",
                            idToken.getIssuedAt(), idToken.getExpiresAt(), Date.from(Instant.now()))),
                    () -> {
                        if (nonce != null)
                            assertEquals(!expired && clientSet && userSet,
                                    idToken.isValid(clientId, nonce), "invalid token");
                        else
                            assertEquals(!expired && clientSet && userSet,
                                    idToken.isValid(clientId), "invalid token");
                    },
                    () -> {
                        if (nonce != null)
                            assertTrue(idToken.nonceIsValid(nonce));
                    }
            );
        }

        IDToken verifySigning(IDToken idToken) {
            Supplier<String> generator = () -> {
                RSAKey token = null;
                try {
                    token = IDTokenKeyGenerator.generate();
                } catch (JOSEException e) {
                    fail("This should never ever happen: " + e.getMessage());
                }
                return token.toJSONString();
            };

            final String actualKey = RemoteKeysServer.rsaKey().toString();
            final String wrongKey = generator.get();
            final String emptyKey = "";

            String accessTokenKey = null;
            try {
                accessTokenKey = AccessTokenKeyGenerator.generate();
            } catch (NoSuchAlgorithmException e) {
                fail("Failed to generate Access Token key");
            }
            final String invalidKey = accessTokenKey;

            String signed = null;
            try {
                signed = idToken.signToString(actualKey);
            } catch (InvalidIDTokenKey | InvalidIDToken e) {
                fail("Failed to sign the ID Token: " + e.getMessage());
            }
            assertNotNull(signed);

            assertThrows(InvalidIDTokenKey.class, () -> {
                idToken.signToString(invalidKey);
            }, "signing with an invalid key");
            assertThrows(InvalidIDTokenKey.class, () -> {
                idToken.signToString(emptyKey);
            }, "signing with an empty key");

            final String sgn = signed;
            assertThrows(InvalidIDToken.class, () -> {
                IDToken.readFromString(sgn, wrongKey);
            }, "reading with a wrong key");
            assertThrows(InvalidIDTokenKey.class, () -> {
                IDToken.readFromString(sgn, invalidKey);
            }, "reading with an invalid key");
            assertThrows(InvalidIDTokenKey.class, () -> {
                IDToken.readFromString(sgn, emptyKey);
            }, "reading with an empty key");
            assertThrows(InvalidIDToken.class, () -> {
                IDToken.readFromString("", actualKey);
            }, "reading of an empty token");
            assertThrows(InvalidIDToken.class, () -> {
                IDToken.readFromString(sgn + UUID.randomUUID(), actualKey);
            }, "reading of an invalid token");


            assertThrows(InvalidIDToken.class, () -> {
                IDToken.readFromString(sgn, new URL(RemoteKeysServer.WRONG_KEYS_URL));
            }, "reading of an invalid remote key");

            IDToken parsed = null;
            try {
                parsed = IDToken.readFromString(sgn, actualKey);
                IDToken parsedRemote = IDToken.readFromString(sgn, new URL(RemoteKeysServer.KEYS_URL));
                assertThat(parsed, sameBeanAs(parsedRemote));
            } catch (InvalidIDToken | InvalidIDTokenKey | MalformedURLException e) {
                fail("Failed to read the ID Token from a string: " + e.getMessage() + e.getCause().getMessage());
            }

            return parsed;
        }

        void verifyToken(IDToken idToken, AdditionalVerification additionalVerification) {
            verifyDefaultClaims(idToken);
            additionalVerification.verify(idToken);
            IDToken parsed = verifySigning(idToken);
            verifyDefaultClaims(parsed);
            additionalVerification.verify(parsed);
        }
    }

    interface AdditionalVerification {
        void verify(IDToken idToken);
    }
}