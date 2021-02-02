package severeone.oidc.auth.tokens.gen;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.RSAKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;

import java.util.HashSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class IDTokenKeyGeneratorTest {

    HashSet<String> keys = new HashSet<>();

    @RepeatedTest(100)
    @DisplayName("Generate 100 unique RSA keys and parse them and corrupted keys")
    void test() {
        RSAKey key = null;
        try {
            key = IDTokenKeyGenerator.generate();
        } catch (JOSEException e) {
            fail("Failed to generate ID Token key");
        }
        assertNotNull(key);

        String keyString = key.toString();
        RSAKey parsed = IDTokenKeyGenerator.parse(keyString);
        assertNotNull(parsed);
        assertEquals(parsed.toString(), keyString);

        String corruptedKey = keyString + UUID.randomUUID();
        parsed = IDTokenKeyGenerator.parse(corruptedKey);
        assertNull(parsed);

        assertFalse(keys.contains(keyString));
        keys.add(keyString);
    }
}