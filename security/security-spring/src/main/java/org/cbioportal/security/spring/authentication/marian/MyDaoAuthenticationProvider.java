package org.cbioportal.security.spring.authentication.marian;

import org.apache.log4j.Logger;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class MyDaoAuthenticationProvider implements AuthenticationProvider, InitializingBean {

    Logger logger = Logger.getLogger(getClass().getName());

    @Override
    public final void afterPropertiesSet() throws Exception {
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        logger.debug(">MyDaoAuthenticationProvider:authenticate: " + authentication);

        // Determine username
        String username = authentication.getName();
        logger.debug(">MyDaoAuthenticationProvider:authenticate:username: " + username);

        UserDetails user;

        user = getUserDetailsService().loadUserByUsername(username);
        if (user == null) {
            logger.debug("User '" + username + "' not found");
            throw new BadCredentialsException("User " + username + " not found; ");
        }

        if (!user.isEnabled()) {
            logger.debug("User is found but disabled");
            throw new BadCredentialsException("User " + username + " is disabled");
        }

   

      //  additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication);
 

        return createSuccessAuthentication(authentication, user);
    }

    protected Authentication createSuccessAuthentication(Authentication authentication, UserDetails user) {
        UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(user, authentication.getCredentials(), user.getAuthorities());
        result.setDetails(authentication.getDetails());

        return result;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
 
    private UserDetailsService userDetailsService;


    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    protected UserDetailsService getUserDetailsService() {
        return userDetailsService;
    }
}
