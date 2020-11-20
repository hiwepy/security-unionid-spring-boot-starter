/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.unionid.authentication;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.fasterxml.jackson.databind.ObjectMapper;

public class UnionIDAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	protected ObjectMapper objectMapper = new ObjectMapper();
	
	public static final String SPRING_SECURITY_FORM_PLATFORM_KEY = "platform";
	public static final String SPRING_SECURITY_FORM_UNIONID_KEY = "unionid";
	public static final String SPRING_SECURITY_FORM_TOKEN_KEY = "token";
	
	private String platformParameter = SPRING_SECURITY_FORM_PLATFORM_KEY;
	private String unionidParameter = SPRING_SECURITY_FORM_UNIONID_KEY;
	private String tokenParameter = SPRING_SECURITY_FORM_TOKEN_KEY;
	
    public UnionIDAuthenticationProcessingFilter(ObjectMapper objectMapper) {
    	super(new AntPathRequestMatcher("/login/unionid", "POST"));
    	this.objectMapper = objectMapper;
    }

    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
    	
    	ServletRequestAttributes requestAttributes = new ServletRequestAttributes(request, response);
		RequestContextHolder.setRequestAttributes(requestAttributes, true);
 
		AbstractAuthenticationToken authRequest = null;
		
		// Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			
			UnionIDLoginRequest loginRequest = objectMapper.readValue(request.getReader(), UnionIDLoginRequest.class);
	 		authRequest = this.authenticationToken( request, loginRequest);

		} else {
			
	 		String platform = obtainPlatform(request);
			String unionid = obtainUnionid(request);
			String token = obtainToken(request);
			authRequest = this.authenticationToken( request, new UnionIDLoginRequest(platform, unionid, token) );
	 		
		}

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);

    }
    
	protected AbstractAuthenticationToken authenticationToken(HttpServletRequest request, UnionIDLoginRequest loginRequest) {
		UnionIDAuthenticationToken token = new UnionIDAuthenticationToken( loginRequest);
		token.setAppId(this.obtainAppId(request));
		token.setAppChannel(this.obtainAppChannel(request));
		token.setAppVersion(this.obtainAppVersion(request));
		return token;
	}

	protected String obtainPlatform(HttpServletRequest request) {
		return request.getParameter(this.getPlatformParameter());
	}

	protected String obtainUnionid(HttpServletRequest request) {
		return request.getParameter(this.getUnionidParameter());
	}
	
	protected String obtainToken(HttpServletRequest request) {
		return request.getParameter(this.getTokenParameter());
	}
	
    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	

	public String getPlatformParameter() {
		return platformParameter;
	}

	public void setPlatformParameter(String platformParameter) {
		this.platformParameter = platformParameter;
	}

	public String getUnionidParameter() {
		return unionidParameter;
	}

	public void setUnionidParameter(String unionidParameter) {
		this.unionidParameter = unionidParameter;
	}

	public String getTokenParameter() {
		return tokenParameter;
	}

	public void setTokenParameter(String tokenParameter) {
		this.tokenParameter = tokenParameter;
	}

}