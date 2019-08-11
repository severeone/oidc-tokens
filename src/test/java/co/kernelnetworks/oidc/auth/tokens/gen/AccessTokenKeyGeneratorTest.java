package co.kernelnetworks.oidc.auth.tokens.gen;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;

import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class AccessTokenKeyGeneratorTest {

    HashSet<String> keys = new HashSet<>();

    @RepeatedTest(100)
    @DisplayName("Generate 100 unique keys and check their format and a format of corrupted keys")
    void test() {
        String generated = null;
        try {
            generated = AccessTokenKeyGenerator.generate();
        } catch (NoSuchAlgorithmException e) {
            fail("Suddenly there's no such algorithm which is really strange: " + e.getMessage());
        }
        assertNotNull(generated);
        final String key = generated;
        assertAll("keys",
                () -> assertTrue(AccessTokenKeyGenerator.checkFormat(key)),
                () -> assertFalse(AccessTokenKeyGenerator.checkFormat(
                        key + UUID.randomUUID()))
        );
        assertFalse(keys.contains(key));
        keys.add(key);
    }
}