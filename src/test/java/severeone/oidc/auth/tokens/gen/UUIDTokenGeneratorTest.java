package severeone.oidc.auth.tokens.gen;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;

import java.util.HashSet;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class UUIDTokenGeneratorTest {

    HashSet<String> uuids = new HashSet<>();

    @RepeatedTest(100)
    @DisplayName("Generating 100 unique tokens")
    void testGenerate() {
        String uuid = UUIDTokenGenerator.generate();
        assertNotNull(UUID.fromString(uuid));
        assertFalse(uuids.contains(uuid));
        uuids.add(uuid);
    }

    @RepeatedTest(100)
    @DisplayName("Checking format of 100 unique tokens")
    void testCheckFormat() {
        String uuid = UUIDTokenGenerator.generate();
        assertAll(
                () -> assertTrue(UUIDTokenGenerator.checkFormat(uuid)),
                () -> assertFalse(UUIDTokenGenerator.checkFormat(uuid + UUID.randomUUID()))
        );
    }
}
