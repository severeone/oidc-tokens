package co.kernelnetworks.oidc.auth.tokens.util;

import com.nimbusds.jose.proc.SecurityContext;

/**
 * Case Medical Research security context. Needed by Nimbus JOSE+JWT classes.
 */

public class CaseMedicalResearchSecurityContext implements SecurityContext {

    public static final String ISSUER = "auth.casemedicalresearch.com";
    public static final String USER_INFO_ENDPOINT = "https://auth.casemedicalresearch.com/auth/userinfo";
    public static final String API_ENDPOINT = "https://my.casemedicalresearch.com/api/v2";

    private CaseMedicalResearchSecurityContext() {}
}
