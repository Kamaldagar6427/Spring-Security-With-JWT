package com.jwt.security.jwtExample.service;

import java.util.List;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.jwt.security.jwtExample.model.AuthenticationResponse;
import com.jwt.security.jwtExample.model.Token;
import com.jwt.security.jwtExample.model.User;
import com.jwt.security.jwtExample.repository.TokenRepository;
import com.jwt.security.jwtExample.repository.UserRepository;

@Service
public class AuthenticationService {

	private final UserRepository repository;
	private final PasswordEncoder passwordEncoder;
	private final JwtService jwtService;
	private final TokenRepository tokenRepository;
	private final AuthenticationManager authenticationManager;

	public AuthenticationService(UserRepository repository, 
			                     PasswordEncoder passwordEncoder, 
			                     JwtService jwtService,
                       		   	 TokenRepository tokenRepository, 
                       		   	 AuthenticationManager authenticationManager) {
		this.repository = repository;
		this.passwordEncoder = passwordEncoder;
		this.jwtService = jwtService;
		this.tokenRepository = tokenRepository;
		this.authenticationManager = authenticationManager;
	}
	
	public AuthenticationResponse register(User request) {
		
		// check if user already exist. if exist then authenticate the user
		if(repository.findByUsername(request.getUsername()).isPresent()) {
			return new AuthenticationResponse(null, "User already exist");
		}
		User user = new User();
		user.setFirstName(request.getFirstName());
		user.setLastName(request.getLastName());
		user.setUsername(request.getUsername());
		user.setPassword(passwordEncoder.encode(request.getPassword()));
		
		user.setRole(request.getRole());
		
		user = repository.save(user);
		
		String jwt = jwtService.generateToken(user);
		
		saveUserToken(jwt, user);
		
		return new AuthenticationResponse(jwt, "User registration was successfull");
	}
	
	public AuthenticationResponse authenticate(User request) {
		authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(
						request.getUsername(), 
						request.getPassword()
				)
		);
		User user = repository.findByUsername(request.getUsername()).orElseThrow();
		String jwt = jwtService.generateToken(user);
		
		revokeAllTokenByUser(user);
		saveUserToken(jwt, user);
		
		return new AuthenticationResponse(jwt, "User login was successful");
	}
	
	private void revokeAllTokenByUser(User user) {
		List<Token> validTokens = tokenRepository.findAllTokensByUser(user.getId());
		if(validTokens.isEmpty()) {
			return;
		}
		validTokens.forEach(t -> {
			t.setLoggedout(true);
		});
	}
	
	private void saveUserToken(String jwt, User user) {
		Token token = new Token();
		token.setToken(jwt);
		token.setLoggedout(false);
		token.setUser(user);
		tokenRepository.save(token);
	}
 }
