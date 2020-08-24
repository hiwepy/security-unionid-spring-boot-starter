package org.springframework.security.boot.unionid.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * UnionID登录认证绑定的参数对象Model
 * 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
public class UnionIDLoginRequest {

	/**
	 * 第三方平台类型
	 */
	private String platform;
	/**
	 * 第三方平台 UnionID
	 */
	private String unionid;
	/**
	 * 第三方平台 Token（部分平台需要进行安全验证）
	 */
	private String token;

	@JsonCreator
	public UnionIDLoginRequest(@JsonProperty("platform") String platform, @JsonProperty("unionid") String unionid,
			@JsonProperty("token") String token) {
		this.platform = platform;
		this.unionid = unionid;
		this.token = token;
	}

	public String getPlatform() {
		return platform;
	}

	public void setPlatform(String platform) {
		this.platform = platform;
	}

	public String getUnionid() {
		return unionid;
	}

	public void setUnionid(String unionid) {
		this.unionid = unionid;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

}
