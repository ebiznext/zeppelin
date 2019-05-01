package org.apache.zeppelin.realm.cdp;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import net.minidev.json.JSONObject;
import org.apache.hadoop.security.authentication.client.AuthenticationException;
import org.apache.hadoop.security.authentication.server.AuthenticationHandler;
import org.apache.hadoop.security.authentication.server.AuthenticationToken;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;
import java.util.Properties;

public class JwtAuthenticationHandler implements AuthenticationHandler {
    private static String ORG = System.getenv("COMET_USER_ORG");
    private static String PROJECT = System.getenv("COMET_USER_PROJECT");
    @Override
    public String getType() {
        return "simple";
    }

    @Override
    public void init(Properties config) throws ServletException {

    }

    @Override
    public void destroy() {

    }

    @Override
    public boolean managementOperation(AuthenticationToken token, HttpServletRequest request, HttpServletResponse response) throws IOException, AuthenticationException {
        return false;
    }

    @Override
    public AuthenticationToken authenticate(HttpServletRequest request, HttpServletResponse response) throws IOException, AuthenticationException {
        AuthenticationToken token;
        String jwt = request.getHeader("Authorization");
        if (jwt == null || !jwt.startsWith("Bearer ")) {
            throw new AuthenticationException("Anonymous requests are disallowed");
        } else {
            jwt = jwt.substring(jwt.indexOf(" "));
            JSONObject payload;
            try {
                JWSObject jwsObject = JWSObject.parse(jwt);
                JWSVerifier verifier = new MACVerifier("secret");
                jwsObject.verify(verifier);
                payload = jwsObject.getPayload().toJSONObject();

            } catch (ParseException | JOSEException e) {
                e.printStackTrace();
                throw new AuthenticationException(e.getMessage());
            }
            String username = payload.getAsString("username");
            String org = payload.getAsString("org");
            String project = payload.getAsString("project");
            if (ORG.equals(org) && PROJECT.equals(project))
                token = new AuthenticationToken(username, jwt, getType());
            else
                token = null;
        }
        return token;
    }
}
