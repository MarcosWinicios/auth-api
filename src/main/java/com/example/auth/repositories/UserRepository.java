package com.example.auth.repositories;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;

import com.example.auth.domain.user.User;

public interface UserRepository extends JpaRepository<User, String>{
	
	public UserDetails findByLogin(String login);
}
