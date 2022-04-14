package com.example.securingweb;

import java.io.IOException;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Component;
import org.springframework.web.context.support.RequestHandledEvent;

@Component
public class AuthenticationEvents {
	@Autowired
	JdbcUserDetailsManager jdbcUserDetailsManager;

	@Autowired
	UserLogginsRepository userLogginsRepository;

//	@Autowired
//	UserLogFailuresRepository userLogFailuresRepository;

	@Autowired
	HttpServletRequest request;



	/* X-Forwarded-For: clientIpAddressOriginal, proxy1, proxy2 */
	private String getClientIP() {
		String xfHeader = request.getHeader("X-Forwarded-For");
		if (xfHeader == null) {
			return request.getRemoteAddr();
		}
		return xfHeader.split(",")[0];
	}

	@EventListener
	public void onSuccess(AuthenticationSuccessEvent success) {
		System.out.println("Youhouh!");
		System.out.println("request : " + request.getRequestURI());

		Object principal = success.getAuthentication().getPrincipal();
		String username;

		if (principal instanceof UserDetails) {
			username = ((UserDetails) principal).getUsername();
		} else {
			username = principal.toString();
		}
		userloggins userloggins = new userloggins();
		userloggins.setDate(new Date().toString());
		userloggins.setUsername(username);
		userloggins.setAction("SUCCESS");
		userloggins.setIp(getClientIP());
		userLogginsRepository.save(userloggins);
	}

	@EventListener
	public void onFailure(AbstractAuthenticationFailureEvent failures) {
		System.out.println("Pfffff!");
		System.out.println("request : " + request.getRequestURI());
		Object principal = failures.getAuthentication().getPrincipal();
		String username;

		if (principal instanceof UserDetails) {
			username = ((UserDetails) principal).getUsername();
		} else {
			username = principal.toString();
		}
		userloggins userloggins = new userloggins();
		userloggins.setDate(new Date().toString());
		userloggins.setUsername(username);
		userloggins.setAction("FAILURES");
		userloggins.setIp(getClientIP());
		userLogginsRepository.save(userloggins);

	}

	@EventListener
	public void onLogout(LogoutSuccessEvent logout) {
		// ...
		System.out.println("logged out 2222!");
		System.out.println("request : " + request.getRequestURI());
		Object principal = logout.getAuthentication().getPrincipal();
		String username;

		if (principal instanceof UserDetails) {
			username = ((UserDetails) principal).getUsername();
		} else {
			username = principal.toString();
		}
		userloggins userloggins = new userloggins();
		userloggins.setDate(new Date().toString());
		userloggins.setUsername(username);
		userloggins.setAction("LOGOUT");
		userloggins.setIp(getClientIP());
		userLogginsRepository.save(userloggins);
		
	}

	@EventListener
	public void onRequestAuthenticationEvent(AbstractAuthenticationEvent request) throws IOException {
		System.out.println("-- AbstractAuthenticationEvent --");
		System.out.println(request);
		Object principal = request.getAuthentication().getPrincipal();
		String username;

		if (principal instanceof UserDetails) {
			username = ((UserDetails) principal).getUsername();
		} else {
			username = principal.toString();
		}

	}

	@EventListener
	public void handleRequestEvent(RequestHandledEvent request) {
		System.out.println("-- RequestHandledEvent --");
		System.out.println(request);
	}


	//	Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	//	String username;

	//	if (principal instanceof UserDetails) {
	//		username = ((UserDetails) principal).getUsername();
	//	} else {
	//		username = principal.toString();
	//	}
}