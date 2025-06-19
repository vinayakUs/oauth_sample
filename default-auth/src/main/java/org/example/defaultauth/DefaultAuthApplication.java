package org.example.defaultauth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({RsaKeyProperties.class})
public class DefaultAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(DefaultAuthApplication.class, args);
    }

}
