package org.cbioportal.security.spring.authentication.marian;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.NullRememberMeServices;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

public class MyUsernamePasswordAuthenticationFilter extends GenericFilterBean implements ApplicationEventPublisherAware, MessageSourceAware {

    Logger logger = Logger.getLogger(getClass().getName());
   
    //~ Instance fields ================================================================================================
    protected ApplicationEventPublisher eventPublisher;
    protected AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private AuthenticationManager authenticationManager;
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
    private RememberMeServices rememberMeServices = new NullRememberMeServices();

    private RequestMatcher requiresAuthenticationRequestMatcher;

    /**
     * The URL destination that this filter intercepts and processes (usually
     * something like <code>/j_spring_security_check</code>)
     *
     * @deprecated use {@link #requiresAuthenticationRequestMatcher} instead
     */
    @Deprecated
    private String filterProcessesUrl;

    private SessionAuthenticationStrategy sessionStrategy = new NullAuthenticatedSessionStrategy();

    private boolean allowSessionCreation = true;

    private AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    //  

    //~ Constructors ===================================================================================================
    /**
     * @param defaultFilterProcessesUrl the default value for
     * <tt>filterProcessesUrl</tt>.
     */
    protected MyUsernamePasswordAuthenticationFilter(String defaultFilterProcessesUrl) {
        this.requiresAuthenticationRequestMatcher = new FilterProcessUrlRequestMatcher(defaultFilterProcessesUrl);
        this.filterProcessesUrl = defaultFilterProcessesUrl;
    }

    public MyUsernamePasswordAuthenticationFilter() {
        this("/j_spring_security_check");
    }

    /**
     * Creates a new instance
     *
     * @param requiresAuthenticationRequestMatcher the {@link RequestMatcher}
     * used to determine if authentication is required. Cannot be null.
     */
    protected MyUsernamePasswordAuthenticationFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        Assert.notNull(requiresAuthenticationRequestMatcher, "requiresAuthenticationRequestMatcher cannot be null");
        this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
    }

    //~ Methods ========================================================================================================
    @Override
    public void afterPropertiesSet() {
        Assert.notNull(authenticationManager, "authenticationManager must be specified");

        if (rememberMeServices == null) {
            rememberMeServices = new NullRememberMeServices();
        }
    }
    @Autowired
    DataSource ds;

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        logger.debug(">doFilter: ds=" + ds);
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        if (!requiresAuthenticationRequestMatcher.matches(request)) {
            chain.doFilter(request, response);
            return;
        }

        logger.debug("doFilter: process authentication");

        try {
            Authentication authResult = attemptAuthentication(request, response);

            sessionStrategy.onAuthentication(authResult, request, response);
            successfulAuthentication(request, response, authResult);
        } catch (AuthenticationException failed) {
            // Authentication failed
            unsuccessfulAuthentication(request, response, failed.getMessage());
        }

    }

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) throws IOException, ServletException {

        logger.debug(">successfulAuthentication");

        SecurityContextHolder.getContext().setAuthentication(authResult);

        rememberMeServices.loginSuccess(request, response, authResult);

        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, String message) throws IOException, ServletException {
        logger.debug(">unsuccessfulAuthentication: " + message);
        SecurityContextHolder.clearContext();
        rememberMeServices.loginFail(request, response);
        onAuthenticationFailure(request, response, message);
    }

    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, String msg) throws IOException, ServletException {
        logger.info("Redirecting to " + failureUrl);
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, msg);
        response.sendRedirect(request.getContextPath()+failureUrl);
    }

    protected AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Deprecated
    public String getFilterProcessesUrl() {
        return filterProcessesUrl;
    }

    /**
     * Sets the URL that determines if authentication is required
     *
     * @param filterProcessesUrl
     * @deprecated use
     * {@link #setRequiresAuthenticationRequestMatcher(RequestMatcher)} instead
     */
    @Deprecated
    public void setFilterProcessesUrl(String filterProcessesUrl) {
        this.requiresAuthenticationRequestMatcher = new FilterProcessUrlRequestMatcher(filterProcessesUrl);
        this.filterProcessesUrl = filterProcessesUrl;
    }

    public final void setRequiresAuthenticationRequestMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.filterProcessesUrl = null;
        this.requiresAuthenticationRequestMatcher = requestMatcher;
    }

    public RememberMeServices getRememberMeServices() {
        return rememberMeServices;
    }

    public void setRememberMeServices(RememberMeServices rememberMeServices) {
        Assert.notNull("rememberMeServices cannot be null");
        this.rememberMeServices = rememberMeServices;
    }

    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setMessageSource(MessageSource messageSource) {
        this.messages = new MessageSourceAccessor(messageSource);
    }

    protected boolean getAllowSessionCreation() {
        return allowSessionCreation;
    }

    public void setAllowSessionCreation(boolean allowSessionCreation) {
        this.allowSessionCreation = allowSessionCreation;
    }

    /**
     * The session handling strategy which will be invoked immediately after an
     * authentication request is successfully processed by the
     * <tt>AuthenticationManager</tt>. Used, for example, to handle changing of
     * the session identifier to prevent session fixation attacks.
     *
     * @param sessionStrategy the implementation to use. If not set a null
     * implementation is used.
     */
    public void setSessionAuthenticationStrategy(SessionAuthenticationStrategy sessionStrategy) {
        this.sessionStrategy = sessionStrategy;
    }

    /**
     * Sets the strategy used to handle a successful authentication. By default
     * a {@link SavedRequestAwareAuthenticationSuccessHandler} is used.
     */
    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler successHandler) {
        Assert.notNull(successHandler, "successHandler cannot be null");
        this.successHandler = successHandler;
    }

    protected AuthenticationSuccessHandler getSuccessHandler() {
        return successHandler;
    }

    private static final class FilterProcessUrlRequestMatcher implements RequestMatcher {

        private final String filterProcessesUrl;

        private FilterProcessUrlRequestMatcher(String filterProcessesUrl) {
            Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
            Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), filterProcessesUrl + " isn't a valid redirect URL");
            this.filterProcessesUrl = filterProcessesUrl;
        }

        public boolean matches(HttpServletRequest request) {
            String uri = request.getRequestURI();
            int pathParamIndex = uri.indexOf(';');

            if (pathParamIndex > 0) {
                // strip everything after the first semi-colon
                uri = uri.substring(0, pathParamIndex);
            }

            if ("".equals(request.getContextPath())) {
                return uri.endsWith(filterProcessesUrl);
            }

            return uri.endsWith(request.getContextPath() + filterProcessesUrl);
        }
    }
    public static final String SPRING_SECURITY_FORM_USERNAME_KEY = "j_username";
    public static final String SPRING_SECURITY_FORM_PASSWORD_KEY = "j_password";
 
    private String usernameParameter = SPRING_SECURITY_FORM_USERNAME_KEY;
    private String passwordParameter = SPRING_SECURITY_FORM_PASSWORD_KEY;

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        String username = request.getParameter(usernameParameter);;
        String password = request.getParameter(passwordParameter);

        if (username == null || password == null) {
            throw new BadCredentialsException("null password or login");
        }

        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);

        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
        
        Authentication r = getAuthenticationManager().authenticate(authRequest);
        additionalAuthenticationChecks(username, password);
        return r;
    }

    protected void additionalAuthenticationChecks(String username, String password) throws AuthenticationException {

        logger.debug(">additionalAuthenticationChecks: username=" + username);

        if (!checkPassword(username, password)) {
            throw new BadCredentialsException("Bad credentials");
        }
    }

    boolean checkPassword(String username, String password) {
        logger.debug(">checkPassword: username= " + username);
        String sql = "SELECT * FROM  users where email=? and password=?";
        boolean r = false;
        try (Connection con = ds.getConnection(); PreparedStatement st = con.prepareStatement(sql)) {
            st.setString(1, username);
            st.setString(2, password);
            ResultSet rs = st.executeQuery();
            r = rs.next();

        } catch (SQLException ex) {
            logger.error("Ex: " + ex);
        }
        logger.debug("<checkPassword: username= " + username + "; right password=" + r);
        return r;
    }

    
    String failureUrl;

    public String getFailureUrl() {
        return failureUrl;
    }

    public void setFailureUrl(String failureUrl) {
        this.failureUrl = failureUrl;
    }

}
