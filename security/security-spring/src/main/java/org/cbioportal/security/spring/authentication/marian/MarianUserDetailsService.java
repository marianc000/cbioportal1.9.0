package org.cbioportal.security.spring.authentication.marian;

import org.cbioportal.model.User;
import org.cbioportal.model.UserAuthorities;
import org.cbioportal.persistence.SecurityRepository;

import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.security.core.userdetails.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import org.springframework.stereotype.Service;

import java.util.List;
import org.apache.log4j.Logger;

@Service
public class MarianUserDetailsService implements UserDetailsService {

    Logger logger = Logger.getLogger(getClass().getName());
    @Autowired
    private SecurityRepository securityRepository;

    @Override
    public UserDetails loadUserByUsername(String username) {

        logger.debug(">loadUserByUsername: " + username);

        User user = securityRepository.getPortalUser(username);

  
  
        UserDetails toReturn = null;
        if (user != null) {
            logger.debug("attempting to fetch portal user authorities, username: " + username);

            UserAuthorities authorities = securityRepository.getPortalUserAuthorities(username);
            List<GrantedAuthority> grantedAuthorities;
            if (authorities != null) {
                logger.debug("loadUserByUsername(), loaded authorities");
                grantedAuthorities = AuthorityUtils.createAuthorityList(authorities.getAuthorities().toArray(new String[authorities.getAuthorities().size()]));
            } else {
                logger.debug("Authorities not found. adding default");
                grantedAuthorities = AuthorityUtils.createAuthorityList("NO_AUTHORITY");
            }
       
        toReturn = new org.springframework.security.core.userdetails.User(username, "nopassword", user.isEnabled(), true, true, true, grantedAuthorities);
        }
        logger.debug("<loadUserByUsername: successfully loaded user: " + username);
        return toReturn;

    }
}
