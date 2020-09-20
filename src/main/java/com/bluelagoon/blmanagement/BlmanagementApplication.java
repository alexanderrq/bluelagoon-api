package com.bluelagoon.blmanagement;

import com.bluelagoon.blmanagement.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class BlmanagementApplication {
	public static void main(String[] args) {
		SpringApplication.run(BlmanagementApplication.class, args);
	}

}
