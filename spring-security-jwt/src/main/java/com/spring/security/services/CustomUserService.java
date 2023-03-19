package com.spring.security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.spring.security.entities.User;
import com.spring.security.repository.UserDetailsRepository;

@Service
public class CustomUserService implements UserDetailsService {

	@Autowired
	UserDetailsRepository userDetailsRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		User user = userDetailsRepository.findByUserName(username);

		if (user == null) {

			throw new UsernameNotFoundException(username);
		}

		return user;
	}

}
