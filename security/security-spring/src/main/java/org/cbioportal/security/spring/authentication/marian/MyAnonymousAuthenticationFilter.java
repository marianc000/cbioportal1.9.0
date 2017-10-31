package org.cbioportal.security.spring.authentication.marian;

import java.io.IOException;
import java.util.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.sql.DataSource;
import static marian.caikovski.redirect.servlet.MyRidirectServlet.IPP_ATTRIBUTE;
import static marian.caikovski.redirect.servlet.MyRidirectServlet.SOARIAN_USERNAME_ATTRIBUTE;
import static marian.caikovski.redirect.servlet.MyRidirectServlet.STUDY_NAME_ATTRIBUTE;
import org.apache.log4j.Logger;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.web.filter.GenericFilterBean;

public class MyAnonymousAuthenticationFilter extends GenericFilterBean implements InitializingBean {

    Logger logger = Logger.getLogger(getClass().getName());
    //~ Instance fields ================================================================================================
 //   private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
  //  private String key;
    private Object principal;
    private List<GrantedAuthority> authorities;
    @Autowired
    DataSource ds;

    public MyAnonymousAuthenticationFilter(String key) {
        logger.debug(">MyAnonymousAuthenticationFilter:constructor2: ds=" + ds);
     //   this.key = key;
        this.principal = "anonymousUser";
        this.authorities = AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS");
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        logger.debug(">doFilter: ds=" + ds);
       
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

        authenticateSoarian((HttpServletRequest) req);

        chain.doFilter(req, res);
    }

    void authenticateSoarian(HttpServletRequest req) {
        HttpSession session = req.getSession();
        Object soarianUser = session.getAttribute(SOARIAN_USERNAME_ATTRIBUTE);
        //  Object ipp = session.getAttribute(IPP_ATTRIBUTE);
        Object studyName = session.getAttribute(STUDY_NAME_ATTRIBUTE);
        logger.debug("soarianUser: " + soarianUser +   "; studyName:" + studyName);
//        if (req.getQueryString() == null) { // it and getParameter somehow does not always work, 
//            logger.warn("very strange getQueryString: " + req.getQueryString());
//        }
        if (soarianUser != null) {
            req.getSession().removeAttribute(SOARIAN_USERNAME_ATTRIBUTE);
            if (studyName != null) {
                req.getSession().removeAttribute(STUDY_NAME_ATTRIBUTE);
                SecurityContextHolder.getContext().setAuthentication(createAuthentication(soarianUser.toString(), studyName.toString()));
                logger.debug("Populated SecurityContextHolder with  token");
            } else {
                logger.warn("studyName attribute is null, did nothing: ");
            }
        } else {
            logger.debug("Soarian user is null, did nothing: ");
        }
    }

    void printAuthentication(Authentication a) {

        logger.debug("\n>getCredentials(): " + a.getCredentials() + "\n>getDetails(): " + a.getDetails() + "\n>getPrincipal()" + a.getPrincipal());

        for (GrantedAuthority at : a.getAuthorities()) {
            logger.debug(">getAuthority(): " + at.getAuthority());
        }

    }
    static String NO_PASSWORD = "noPassword";

    protected Authentication createAuthentication(String soarianUser, String studyName) {
        //   (String email, List<String> authorities)
        //  List<String> authorityList = new LinkedList<>();
        //  authorityList.add("cbioportal:ALL");
        //  UserAuthorities authorities = new UserAuthorities(soarianUser, authorityList);
        //    List<GrantedAuthority> grantedAuthorities = AuthorityUtils.createAuthorityList("cbioportal:ALL");
        // String studyName = getStudyName(ipp, ds);
        //  logger.debug("studyName=" + studyName);
        List<GrantedAuthority> grantedAuthorities = AuthorityUtils.createAuthorityList("cbioportal:" + studyName);
        UserDetails user = new User(soarianUser, NO_PASSWORD, grantedAuthorities);
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user, NO_PASSWORD, user.getAuthorities());
        // auth.setDetails(authenticationDetailsSource.buildDetails(request));

        return auth;
    }

//    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
//        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
//        this.authenticationDetailsSource = authenticationDetailsSource;
//    }

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
//    @Deprecated
//    public void setKey(String key) {
//        this.key = key;
//    }

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
