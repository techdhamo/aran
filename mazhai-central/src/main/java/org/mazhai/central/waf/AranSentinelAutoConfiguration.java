package org.mazhai.central.waf;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * AranSentinel WAF Auto-Configuration
 * 
 * Automatically registers the WAF filter when @EnableAranSentinel is present
 */
@Configuration
@EnableConfigurationProperties(WafConfig.class)
public class AranSentinelAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AranSentinelWafFilter aranSentinelWafFilter(WafConfig wafConfig) {
        return new AranSentinelWafFilter(wafConfig);
    }

    @Bean
    public FilterRegistrationBean<AranSentinelWafFilter> aranSentinelFilterRegistration(
        AranSentinelWafFilter filter
    ) {
        FilterRegistrationBean<AranSentinelWafFilter> registration = new FilterRegistrationBean<>();
        registration.setFilter(filter);
        
        // IMPORTANT: Only apply WAF to business endpoints, not RASP infrastructure
        // The filter itself has shouldSkipWaf() logic, but we optimize by only
        // registering for /api/* and letting the filter skip specific paths
        registration.addUrlPatterns("/api/*");
        
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.setName("AranSentinelWafFilter");
        return registration;
    }
}
