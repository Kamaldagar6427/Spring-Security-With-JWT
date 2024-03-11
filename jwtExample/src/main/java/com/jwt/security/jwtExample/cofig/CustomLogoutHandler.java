package com.jwt.security.jwtExample.cofig;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import com.jwt.security.jwtExample.model.Token;
import com.jwt.security.jwtExample.repository.TokenRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomLogoutHandler implements LogoutHandler{
	
	private final TokenRepository tokenRepository;
	
	

	public CustomLogoutHandler(TokenRepository tokenRepository) {
		this.tokenRepository = tokenRepository;
	}



	@Override
	public void logout(HttpServletRequest request, 
			           HttpServletResponse response, 
			           Authentication authentication) {
		String authHeader = request.getHeader("Authorization");
		
		if(authHeader == null || !authHeader.startsWith("Bearer")) {
			return;
		}
		
		String token = authHeader.substring(7);
		Token storedToken = tokenRepository.findByToken(token).orElse(null);
		
		if(storedToken != null) {
			storedToken.setLoggedout(true);
			tokenRepository.save(storedToken);
		}
	}

}
