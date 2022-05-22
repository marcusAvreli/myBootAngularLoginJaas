
package myBootAngularLoginJaas.security.jwt;

import java.io.IOException;


import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;


import myBootAngularLoginJaas.security.services.UserDetailsServiceImpl;;



public class AuthTokenFilter extends OncePerRequestFilter {

	@Autowired
	private JwtUtils jwtUtils;


	@Autowired
	private UserDetailsServiceImpl userDetailsService;


	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		logger.info("[doFilterInternal]:1");
		 response.setHeader("Access-Control-Allow-Origin", "*");
         response.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
         response.setHeader("Access-Control-Max-Age", "3600");
         response.setHeader("Access-Control-Allow-Headers", "authorization, content-type, xsrf-token");
         response.addHeader("Access-Control-Expose-Headers", "xsrf-token");
         if ("OPTIONS".equals(request.getMethod())) {
             response.setStatus(HttpServletResponse.SC_OK);
         }
         logger.info("[doFilterInternal]:2");
		try {
			logger.info("[doFilterInternal]:3");
			String jwt = parseJwt(request);
			logger.info("[doFilterInternal]:jwt ==> "+jwt);
			if (jwt != null && jwtUtils.validateJwtToken(jwt)) {
				String username = jwtUtils.getUserNameFromJwtToken(jwt);
				logger.info("[doFilterInternal]:5");
				UserDetails userDetails = userDetailsService.loadUserByUsername(username);
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				logger.info("[doFilterInternal]:6");
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				logger.info("[doFilterInternal]:7");
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (Exception e) {
			logger.error("Cannot set user authentication: {}", e);
		}
		logger.info("[doFilterInternal]:8");
		filterChain.doFilter(request, response);
	}

	private String parseJwt(HttpServletRequest request) {
		logger.info("[parseJwt]1");
		String headerAuth = request.getHeader("Authorization");
		logger.info("[parseJwt]2");
		if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
			logger.info("[parseJwt]3");
			return headerAuth.substring(7, headerAuth.length());
		}
		logger.info("[parseJwt]4");
		return null;
	}
}