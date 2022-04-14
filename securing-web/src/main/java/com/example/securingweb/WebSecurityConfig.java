package com.example.securingweb;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	public DataSource dataSource;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(jdbcUserDetailsManager()).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.authorizeRequests().antMatchers("/", "/home", "/newaccount").permitAll().anyRequest().authenticated().and()
//				.formLogin().loginPage("/login").permitAll().and().logout().permitAll();

		http.authorizeRequests().antMatchers("/", "/home", "/newaccount","/invalidSession.html").permitAll().and().authorizeRequests()
				.antMatchers("/admin/**").hasAnyRole("ADMIN").antMatchers("/user/**").hasAnyRole("USER").and().authorizeRequests().antMatchers("/admin/**").hasAnyRole("ADMIN").antMatchers("/user/**").hasAnyRole("USER").anyRequest()
				.authenticated().and().formLogin().loginPage("/login").permitAll().and().logout().permitAll();

		/* Logout management */
		http.logout(logout -> logout

				.logoutSuccessUrl("/home").invalidateHttpSession(true));

		/* Session management */
		http.sessionManagement(session -> session.invalidSessionUrl("/invalidSession.html"));
		http.logout(logout -> logout.deleteCookies("JSESSIONID"));

		http.sessionManagement(session -> session.maximumSessions(1));
//		http.sessionManagement(session -> session.maximumSessions(1).maxSessionsPreventsLogin(true));

		/* Remember-me */
		http.rememberMe().key("uniqueAndSecret").tokenValiditySeconds(86400);
		
		/* Hierarchical Roles*/
		http
        .authorizeRequests()
             .expressionHandler(webExpressionHandler());
		
		
	}

//	@Bean
//	@Override
//	public UserDetailsService userDetailsService() {
//		UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password").roles("USER")
//				.build();
//
//		return new InMemoryUserDetailsManager(user);
//	}

//	@Bean
//	UserDetailsManager users(DataSource dataSource) {
////		UserDetails user = User.builder()
////			.username("user")
////			.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
////			.roles("USER")
////			.build();
////		UserDetails admin = User.builder()
////			.username("admin")
////			.password("{bcrypt}$2a$10$GRLdNijSQMUvl/au9ofL.eDwmoohzzS7.rmNSJZ.0FxO/BTk76klW")
////			.roles("USER", "ADMIN")
////			.build();
//		JdbcUserDetailsManager users = new JdbcUserDetailsManager(dataSource);
////		users.createUser(user);
////		users.createUser(admin);
//		return users;
//	}

	@Bean
	public JdbcUserDetailsManager jdbcUserDetailsManager() {
		JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();
		jdbcUserDetailsManager.setDataSource(dataSource);

		return jdbcUserDetailsManager;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		return passwordEncoder;
//		return new BCryptPasswordEncoder();
	}

	/* Session management */
	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

	/* Hierarchical Roles */
	@Bean
	public RoleHierarchyImpl roleHierarchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_STAFF\n" + "ROLE_STAFF > ROLE_USER\n" + "ROLE_USER > ROLE_GUEST");
		return roleHierarchy;
	}

//	@Bean
//	public RoleHierarchyVoter roleVoter() {
//		return new RoleHierarchyVoter(roleHierarchy());
//	}

	private SecurityExpressionHandler<FilterInvocation> webExpressionHandler() {
		DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
		defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchy());
		return defaultWebSecurityExpressionHandler;
	}

}