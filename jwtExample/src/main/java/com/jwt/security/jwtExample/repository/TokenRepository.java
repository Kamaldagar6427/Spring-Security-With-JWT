package com.jwt.security.jwtExample.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import com.jwt.security.jwtExample.model.Token;

public interface TokenRepository extends JpaRepository<Token, Integer>{

	@Query("""
			select t from Token t inner join User u on t.user.id = u.id
			where t.user.id = :userId and t.loggedout = false
			""")
	List<Token> findAllTokensByUser(Integer userId);
	
	Optional<Token> findByToken(String token);
}
