package org.mazhai.central.waf;

import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * Enable AranSentinel WAF for Spring Boot Application
 * 
 * Drop-in Zero-Trust Hardware Attestation Gateway
 * 
 * Usage:
 * ```java
 * @SpringBootApplication
 * @EnableAranSentinel
 * public class MyFintechApplication {
 *     public static void main(String[] args) {
 *         SpringApplication.run(MyFintechApplication.class, args);
 *     }
 * }
 * ```
 * 
 * Configuration (application.yml):
 * ```yaml
 * aran:
 *   sentinel:
 *     waf:
 *       block-rooted: true
 *       block-hooked: true
 *       block-emulator: true
 *       block-tampered: true
 * ```
 * 
 * All @RestController endpoints are automatically protected with:
 * - Hardware signature verification
 * - Device posture validation
 * - Anti-replay protection
 * - MITM detection
 * - OWASP Top 10 blocking
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AranSentinelAutoConfiguration.class)
public @interface EnableAranSentinel {
}
