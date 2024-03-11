package com.jwt.security.jwtExample.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

	@GetMapping("/demo")
	public ResponseEntity<String> demo() {
		return ResponseEntity.ok("Hello User");
	}
	
	@GetMapping("/admin")
	public ResponseEntity<String> adminOnly() {
		return ResponseEntity.ok("Hello Admin");
	}
}
