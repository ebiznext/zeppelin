package org.apache.zeppelin.realm.cdp;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import net.minidev.json.JSONObject;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.web.filter.authc.AuthenticatingFilter;

import javax.naming.NamingException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.text.ParseException;

public class JwtFilter extends AuthenticatingFilter {
    private String ORG = System.getenv("COMET_USER_ORG");
    private String PROJECT = System.getenv("COMET_USER_PROJECT");

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String jwt = httpRequest.getHeader("Authorization");
        if (jwt == null || !jwt.startsWith("Bearer ")) {
            return createToken("", "", request, response);
        }
        jwt = jwt.substring(jwt.indexOf(" "));
        JSONObject payload;
        try {
            JWSObject jwsObject = JWSObject.parse(jwt);
            JWSVerifier verifier = new MACVerifier("secret");
            jwsObject.verify(verifier);
            payload = jwsObject.getPayload().toJSONObject();

        } catch (ParseException | JOSEException e) {
            e.printStackTrace();
            throw new NamingException(e.getMessage());
        }
        String username = payload.getAsString("username");
        String org = payload.getAsString("org");
        String project = payload.getAsString("project");
        if (ORG.equals(org) && PROJECT.equals(project))
            return createToken(username, jwt, request, response);
        else
            return createToken("", "", request, response);
    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletResponse res = (HttpServletResponse) response;
        res.setStatus(HttpServletResponse.SC_FORBIDDEN);
        return false;
    }
}
