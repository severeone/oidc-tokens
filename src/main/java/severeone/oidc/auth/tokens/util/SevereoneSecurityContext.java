package severeone.oidc.auth.tokens.util;

import com.nimbusds.jose.proc.SecurityContext;

/**
 * Severeone security context. Needed by Nimbus JOSE+JWT classes.
 */

public class SevereoneSecurityContext implements SecurityContext {

    public static final String ISSUER = "severeone.xyz";
    public static final String USER_INFO_ENDPOINT = "https://severeone.xyz/userinfo";
    public static final String API_ENDPOINT = "https://severeone.xyz/api/v2";

    private SevereoneSecurityContext() {}
}
