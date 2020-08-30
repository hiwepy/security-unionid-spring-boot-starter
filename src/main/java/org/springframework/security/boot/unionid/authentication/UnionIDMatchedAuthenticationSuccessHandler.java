package org.springframework.security.boot.unionid.authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;

import com.alibaba.fastjson.JSONObject;

/**
 * UnionID 认证 (authentication)成功回调器：讲认证信息写回前端
 * @author 		： <a href="https://github.com/hiwepy">hiwepy</a>
 */
public class UnionIDMatchedAuthenticationSuccessHandler implements MatchedAuthenticationSuccessHandler {
   
	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	
	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.isAssignableFrom(authentication.getClass(), UnionIDAuthenticationToken.class);
	}

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
    	
    	// 设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		// 国际化后的异常信息
		String message = messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey(), LocaleContextHolder.getLocale());
		// 写出JSON
		AbstractAuthenticationToken token = (AbstractAuthenticationToken) authentication;
		// 利用登陆用户信息
		SecurityPrincipal principal = (SecurityPrincipal) token.getPrincipal();
		JSONObject.writeJSONString(response.getWriter(), AuthResponse.success(message, principal.toPayload()));
    	 
    }

}
