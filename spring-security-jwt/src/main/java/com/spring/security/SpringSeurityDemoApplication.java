package com.spring.security;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.spring.security.entities.Authority;
import com.spring.security.entities.User;
import com.spring.security.repository.UserDetailsRepository;

@SpringBootApplication
public class SpringSeurityDemoApplication {

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private UserDetailsRepository userDetailsRepository;

	public static void main(String[] args) {
		SpringApplication.run(SpringSeurityDemoApplication.class, args);
	}

	@PostConstruct
	protected void init() {

		List<Authority> authoriyList = new ArrayList<Authority>();

		authoriyList.add(createAuthority("USER", "User role"));
		authoriyList.add(createAuthority("ADMIN", "Admin role"));

		User user = new User();
		user.setUserName("pradeep456");
		user.setFirstName("Pradeep");
		user.setLastName("K");
		user.setPassword(passwordEncoder.encode("test@123"));
		user.setEnabled(true);
		user.setAuthorities(authoriyList);

		userDetailsRepository.save(user);

	}

	private Authority createAuthority(String roleCode, String roleDescription) {

		Authority authority = new Authority();
		authority.setRoleCode(roleCode);
		authority.setRoleDescription(roleDescription);

		return authority;

	}

}
