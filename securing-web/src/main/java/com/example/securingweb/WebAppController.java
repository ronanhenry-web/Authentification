package com.example.securingweb;


import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
		import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
		import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class WebAppController {
	@Autowired
	JdbcUserDetailsManager jdbcUserDetailsManager;
	@Autowired
	PasswordEncoder passwordEncoder;
	@Autowired
	UserLogginsRepository userLogginsRepository;
	
	/**
	 * Méthode pour récupérer la page de création d'un nouveau utilisateur	
	 * @param model
	 * @return envoyer vers la nouvelle page de création
	 */
	@GetMapping("/newaccount")
	public String userForm(Model model) {
		model.addAttribute("user", new UsernamePassword());
		return "newaccount";
	}

	@PostMapping("/newaccount")
	public String newaccountSubmit(@ModelAttribute UsernamePassword user, Model model) {
			if(!jdbcUserDetailsManager.userExists(user.getUsername())) {
				jdbcUserDetailsManager.createUser(
						User.withUsername(user.getUsername()).password(passwordEncoder.encode(user.getPassword())).roles(user.getRole()).build());
				model.addAttribute("greeting", user);
				
				return "result";
			} else {
				System.out.println("Compte déja existant !!!");
				String compteExistant = "Compte déja existant !!!";
				model.addAttribute("compteExistant", compteExistant);
				model.addAttribute("user", user);
				
				return "newaccount";
			}
		}
	
	
//	------------------------------------------------------------------------------------------- \\
	
	
	@GetMapping("/profil")
	public String profilForm(Model model) {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String username;
		
		if(principal instanceof UserDetails) {
			username = ((UserDetails) principal).getUsername();
		} else {
			username = principal.toString();
		}
		
		UserProperties userProperties = new UserProperties();
		userProperties.setUsername(username);
		
		model.addAttribute("userProperties", userProperties);
		
		return "profil";
	}

	@PostMapping("/profil")
	public String profilSubmit(@ModelAttribute UserProperties profil, Model model) {	
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String username;
		
		if(principal instanceof UserDetails) {
			username = ((UserDetails) principal).getUsername();
		} else {
			username = principal.toString();
		}
		
		UserDetails userDetails = jdbcUserDetailsManager.loadUserByUsername(username);
		
		if(!passwordEncoder.matches(profil.getPassword(), userDetails.getPassword())) {
			String error_passwordChanging_message = "Erreur";
			model.addAttribute("errorChangingPassword", error_passwordChanging_message);
			
			return "profil";
		} else {
			jdbcUserDetailsManager.changePassword(profil.getPassword(), passwordEncoder.encode(profil.getNewPassword()));
		}
		
		System.out.println("---------------------------START----------------------------------"); 
		System.out.println(profil.getPassword()); 
		System.out.println(profil.getNewPassword());
		System.out.println(passwordEncoder.encode(profil.getNewPassword()));
//		System.out.println(userDetails.getPassword());
//		System.out.println(passwordEncoder.encode(profil.getPassword()));
		System.out.println("----------------------------END---------------------------------"); 
		
		model.addAttribute("userProperties", profil);

		return "home";
	}
	
	@GetMapping("/logs")
	public String logs(Model model) {
		Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		String username;
		
		if(principal instanceof UserDetails) {
			username = ((UserDetails) principal).getUsername();
		} else {
			username = principal.toString();
		}
		List<userloggins> log = userLogginsRepository.findByUsername(username);
		model.addAttribute("logs", log);
		
		return "userloggins";
	}
 	
}
