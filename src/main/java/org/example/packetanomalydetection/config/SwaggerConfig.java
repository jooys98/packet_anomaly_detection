package org.example.packetanomalydetection.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;

/**
 * Swagger/OpenAPI 설정
 */
@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI().openapi("3.0.0") // openAPI 버전 명시
                .components(new Components())
                .info(apiInfo());
    }

    private Info apiInfo() {
        return new Info()
                .title("Network Security Monitor API")
                .description("네트워크 보안 모니터링 시스템 REST API")
                .contact(new Contact()
                        .name("주윤수")
                        .email("jooys98@naver.com")
                        .url("https://github.com/jooys98/packet_anomaly_detection.git"))
                .version("1.0.0");
    }
}
