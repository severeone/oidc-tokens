package co.kernelnetworks.oidc.auth.tokens;

import co.kernelnetworks.oidc.auth.tokens.gen.IDTokenKeyGenerator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

import static org.junit.jupiter.api.Assertions.fail;

public class RemoteKeysServer implements Runnable {

    public static final String KEYS_URL = "http://localhost:8000/keys";
    public static final String WRONG_KEYS_URL = "http://localhost:8000/wrongkeys";

    @Override
    public void run() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
            server.createContext("/keys", new RemoteKeyHandler());
            server.createContext("/wrongkeys", new RemoteWrongKeyHandler());
            server.setExecutor(null); // creates a default executor
            server.start();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static RSAKey rsaKey() {
        return RemoteKeyHandler.rsaKey;
    }

    public static RSAKey wrongRsaKey() {
        return RemoteWrongKeyHandler.rsaWrongKey;
    }

    static class RemoteKeyHandler implements HttpHandler {

        static RSAKey rsaKey;

        static {
            try {
                rsaKey = IDTokenKeyGenerator.generate();
            } catch (JOSEException e) {
                fail("This should never ever happen: " + e.getMessage());
            }
        }

        @Override
        public void handle(HttpExchange t) throws IOException {
            JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
            String response = jwkSet.toString();
            t.sendResponseHeaders(200, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }

    static class RemoteWrongKeyHandler implements HttpHandler {

        static RSAKey rsaWrongKey;

        static {
            try {
                rsaWrongKey = IDTokenKeyGenerator.generate();
            } catch (JOSEException e) {
                fail("This should never ever happen: " + e.getMessage());
            }
        }

        @Override
        public void handle(HttpExchange t) throws IOException {
            JWKSet jwkSet = new JWKSet(rsaWrongKey.toPublicJWK());
            String response = jwkSet.toString();
            t.sendResponseHeaders(200, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}
