package com.article.task21;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@SpringBootApplication
@EnableTransactionManagement
public class Task21Application {

	public static void main(String[] args) {
		SpringApplication.run(Task21Application.class, args);
	}

}
