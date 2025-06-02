package org.example.packetanomalydetection.config;

import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.License;

/**
 * Swagger/OpenAPI 설정
 */
@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI securityMonitorOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Network Security Monitor API")
                        .description("네트워크 보안 모니터링 시스템 REST API")
                        .version("v1.0")
                        .contact(new Contact()
                                .name("Security Monitor Team")
                                .email("security@monitor.com")
                                .url("https://github.com/security-monitor"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")));
    }
}
