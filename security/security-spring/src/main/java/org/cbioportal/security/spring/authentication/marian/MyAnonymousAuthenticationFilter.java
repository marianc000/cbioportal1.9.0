package org.cbioportal.security.spring.authentication.marian;

import java.io.IOException;
import java.util.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import static marian.caikovski.redirect.servlet.MyRidirectServlet.SOARIAN_USERNAME_ATTRIBUTE;
import static marian.caikovski.utils.DatabaseUtil.getStudyName;
import org.apache.log4j.Logger;

import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

public class MyAnonymousAuthenticationFilter extends GenericFilterBean implements InitializingBean {

    Logger logger = Logger.getLogger(getClass().getName());
    //~ Instance fields ================================================================================================
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private String key;
    private Object principal;
    private List<GrantedAuthority> authorities;
    @Autowired
    DataSource ds;

    public MyAnonymousAuthenticationFilter(String key) {
        logger.debug(">MyAnonymousAuthenticationFilter:constructor2: ds=" + ds);
        this.key = key;
        this.principal = "anonymousUser";
        this.authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        logger.debug(">doFilter: ds=" + ds);
        HttpServletRequest request = (HttpServletRequest) req;
        Authentication a = SecurityContextHolder.getContext().getAuthentication();

        if (a == null) {

            logger.debug("No token: ");
            //   authenticateSoarian(request);
        } else {
            logger.debug("SecurityContextHolder contained token");
            printAuthentication(a);
            if (!a.isAuthenticated()) {
                logger.debug("But the Token is anonymous");
                //  authenticateSoarian(request);
            }
        }

        authenticateSoarian(request);

        chain.doFilter(req, res);
    }
 

    void authenticateSoarian(HttpServletRequest req) {
        Object soarianUser = req.getSession().getAttribute(SOARIAN_USERNAME_ATTRIBUTE);

        logger.debug("soarianUser: " + soarianUser);
        if (soarianUser != null) {
            String ipp = req.getParameter("case_id");
            logger.debug("case_id: " + ipp);
            SecurityContextHolder.getContext().setAuthentication(createAuthentication(req, soarianUser.toString(), ipp));
            req.getSession().removeAttribute(SOARIAN_USERNAME_ATTRIBUTE);
            logger.debug("Populated SecurityContextHolder with  token: ");
        } else {
            logger.debug("Soarian user is null, did nothing: ");
        }
    }

    void printAuthentication(Authentication a) {

        logger.debug(">getCredentials(): " + a.getCredentials() + "\n>getDetails(): " + a.getDetails() + "\n>getPrincipal()" + a.getPrincipal());

        for (GrantedAuthority at : a.getAuthorities()) {
            logger.debug(">getAuthority(): " + at.getAuthority());
        }

    }
    static String NO_PASSWORD = "noPassword";

    protected Authentication createAuthentication(HttpServletRequest request, String soarianUser, String ipp) {
        //   (String email, List<String> authorities)
        //  List<String> authorityList = new LinkedList<>();
        //  authorityList.add("cbioportal:ALL");
        //  UserAuthorities authorities = new UserAuthorities(soarianUser, authorityList);
        //    List<GrantedAuthority> grantedAuthorities = AuthorityUtils.createAuthorityList("cbioportal:ALL");
        String studyName = getStudyName(ipp, ds);
        logger.debug("studyName=" + studyName);
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils.createAuthorityList("cbioportal:" + studyName);
        UserDetails user = new User(soarianUser, NO_PASSWORD, grantedAuthorities);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user, NO_PASSWORD, user.getAuthorities());
        auth.setDetails(authenticationDetailsSource.buildDetails(request));

        return auth;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public Object getPrincipal() {
        return principal;
    }

    public List<GrantedAuthority> getAuthorities() {
        return authorities;
    }

    /**
     *
     * @deprecated use constructor injection instead
     */
    @Deprecated
    public void setKey(String key) {
        this.key = key;
    }

    /**
     *
     * @deprecated use constructor injection instead
     */
    @Deprecated
    public void setUserAttribute(UserAttribute userAttributeDefinition) {
        this.principal = userAttributeDefinition.getPassword();
        this.authorities = userAttributeDefinition.getAuthorities();
    }
}
