package org.springframework.security.boot;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@ConfigurationProperties(prefix = SecurityUnionIDProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityUnionIDProperties {

	public static final String PREFIX = "spring.security.unionid";

	/** Whether Enable UnionID Authentication. */
	private boolean enabled = false;

}
