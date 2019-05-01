package org.apache.zeppelin.realm.cdp;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.realm.ldap.LdapContextFactory;
import org.apache.zeppelin.realm.LdapRealm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingException;

public class JwtLdapRealm extends LdapRealm {
    private static final Logger log = LoggerFactory.getLogger(JwtLdapRealm.class);

    private String ORG = System.getenv("COMET_USER_ORG");
    private String PROJECT = System.getenv("COMET_USER_PROJECT");

    @Override
    protected AuthenticationInfo queryForAuthenticationInfo(AuthenticationToken token,
                                                            LdapContextFactory ldapContextFactory) throws NamingException {
        Object principal = token.getPrincipal();
        Object credentials = token.getCredentials();
/*
        //AuthenticationInfo info = super.queryForAuthenticationInfo(token, ldapContextFactory);
        JSONObject json = new JSONObject();
        json.put("name", "student");
        JSONArray array = new JSONArray();
        JSONObject item = new JSONObject();
        item.put("information", "test");
        item.put("id", 3);
        item.put("name", "course1");
        array.add(item);
        json.put("course", array);
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload(json));
*/
        log.debug("Authenticating user '{}' through LDAP", principal);

        principal = getLdapPrincipal(token);

        AuthenticationInfo info = createAuthenticationInfo(token, principal, credentials, null);

        // Credentials were verified. Verify that the principal has all allowedRulesForAuthentication
        if (!hasAllowedAuthenticationRules(info.getPrincipals(), ldapContextFactory)) {
            throw new NamingException("Principal does not have any of the allowedRolesForAuthentication");
        }
        return info;
    }

}
