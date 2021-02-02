package severeone.oidc.auth.tokens;

import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.params.provider.Arguments.arguments;

class CustomClaimsProvider implements ArgumentsProvider {
    @Override
    public Stream<? extends Arguments> provideArguments(ExtensionContext context) throws Exception {
        return Stream.of(
                arguments(String.class, String.class.getSimpleName(), "string claim", false),
                arguments(Integer.class, Integer.class.getSimpleName(), 12345, false),
                arguments(Long.class, Long.class.getSimpleName(), 12345L, false),
                arguments(Float.class, Float.class.getSimpleName(), 123.45f, false),
                arguments(Double.class, Double.class.getSimpleName(), 123.45, false),
                arguments(Boolean.class, Boolean.class.getSimpleName(), true, false),
                arguments(List.class, "List<String>", new ArrayList<String>(){{
                    add("one");
                    add("two");
                    add("three");
                }}, false),
                arguments(JSONObject.class, JSONObject.class.getSimpleName(),
                        (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(
                                "{\"key1\":\"value1\",\"key2\":{\"key3\":\"value3\"}}"),
                        false
                ),
                arguments(Date.class, Date.class.getSimpleName(), Date.from(Instant.now()), true),
                arguments(Object.class, "String as Object", "string as object", false)
        );
    }
}
