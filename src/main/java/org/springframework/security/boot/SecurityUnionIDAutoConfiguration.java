package org.springframework.security.boot;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.unionid.authentication.UnionIDAuthenticationProvider;
import org.springframework.security.boot.unionid.authentication.UnionIDMatchedAuthenticationEntryPoint;
import org.springframework.security.boot.unionid.authentication.UnionIDMatchedAuthenticationFailureHandler;
import org.springframework.security.boot.unionid.authentication.UnionIDMatchedAuthenticationSuccessHandler;

@Configuration
@AutoConfigureBefore(SecurityBizAutoConfiguration.class)
@ConditionalOnProperty(prefix = SecurityUnionIDProperties.PREFIX, value = "enabled", havingValue = "true")
@EnableConfigurationProperties({ SecurityUnionIDProperties.class })
public class SecurityUnionIDAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean
	public UnionIDMatchedAuthenticationEntryPoint unionidMatchedAuthenticationEntryPoint() {
		return new UnionIDMatchedAuthenticationEntryPoint();
	}

	@Bean
	@ConditionalOnMissingBean
	public UnionIDMatchedAuthenticationFailureHandler unionidMatchedAuthenticationFailureHandler() {
		return new UnionIDMatchedAuthenticationFailureHandler();
	}
	
	
	@Bean
	@ConditionalOnMissingBean
	public UnionIDMatchedAuthenticationSuccessHandler unionidMatchedAuthenticationSuccessHandler(JwtPayloadRepository payloadRepository) {
		return new UnionIDMatchedAuthenticationSuccessHandler(payloadRepository);
	}
	
	@Bean
	@ConditionalOnMissingBean
	public UnionIDAuthenticationProvider unionidAuthenticationProvider(UserDetailsServiceAdapter userDetailsService) {
		return new UnionIDAuthenticationProvider(userDetailsService);
	}

}
