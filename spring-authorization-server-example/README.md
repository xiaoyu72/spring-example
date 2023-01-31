什么是Spring Authorization Server？

> Spring Authorization Server 是一个框架，提供了[OAuth 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05)和[OpenID Connect 1.0](https://openid.net/specs/openid-connect-core-1_0.html)规范以及其他相关规范的实现。 它建立在[Spring Security](https://spring.io/projects/spring-security)之上，为构建 OpenID Connect 1.0 Identity Providers 和 OAuth2 Authorization Server 产品提供安全、轻量级和可定制的基础。

# 从一个Demo开始

## 最小配置搭建

学习第一步：搭建一个Spring Authorization Server Demo

1. `pom`依赖

   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
   	<modelVersion>4.0.0</modelVersion>
   	<parent>
   		<groupId>org.springframework.boot</groupId>
   		<artifactId>spring-boot-starter-parent</artifactId>
   		<version>2.7.4</version>
   		<relativePath/> <!-- lookup parent from repository -->
   	</parent>
   	<groupId>com.xiao.server</groupId>
   	<artifactId>spring-authorization-server-example</artifactId>
   	<version>0.1</version>
   	<name>spring-authorization-server-example</name>
   	<description>Spring Authorization Server Example</description>
   	<properties>
   		<java.version>1.8</java.version>
   	</properties>
   	<dependencies>
   		<dependency>
   			<groupId>org.springframework.boot</groupId>
   			<artifactId>spring-boot-starter</artifactId>
   		</dependency>
   
   		<dependency>
   			<groupId>org.springframework.boot</groupId>
   			<artifactId>spring-boot-starter-web</artifactId>
   		</dependency>
   
   		<dependency>
   			<groupId>org.springframework.boot</groupId>
   			<artifactId>spring-boot-starter-test</artifactId>
   			<scope>test</scope>
   		</dependency>
   
   		<!-- Spring Authorization Server -->
   		<dependency>
   			<groupId>org.springframework.security</groupId>
   			<artifactId>spring-security-oauth2-authorization-server</artifactId>
   			<version>0.3.1</version>
   		</dependency>
   	</dependencies>
   
   	<build>
   		<plugins>
   			<plugin>
   				<groupId>org.springframework.boot</groupId>
   				<artifactId>spring-boot-maven-plugin</artifactId>
   			</plugin>
   		</plugins>
   	</build>
   </project>
   ```

2. `Configuration`配置

   ```java
   @Configuration
   @EnableWebSecurity(debug = true) // 开启SpringWebSecurity
   public class SecurityConfig {
   
   
       /**
        * 这是个Spring security 的过滤器链，默认会配置
        * <p>
        * OAuth2 Authorization endpoint
        * <p>
        * OAuth2 Token endpoint
        * <p>
        * OAuth2 Token Introspection endpoint
        * <p>
        * OAuth2 Token Revocation endpoint
        * <p>
        * OAuth2 Authorization Server Metadata endpoint
        * <p>
        * JWK Set endpoint
        * <p>
        * OpenID Connect 1.0 Provider Configuration endpoint
        * <p>
        * OpenID Connect 1.0 UserInfo endpoint
        * <p>
        * 这些协议端点，只有配置了他才能够访问的到接口地址（类似mvc的controller）。
        * </p>
        * @param http
        * @return
        * @throws Exception
        */
       @Bean
       @Order(1)
       public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
               throws Exception {
           OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
           http
                   // Redirect to the login page when not authenticated from the
                   // authorization endpoint
                   .exceptionHandling((exceptions) -> exceptions
                           .authenticationEntryPoint(
                                   new LoginUrlAuthenticationEntryPoint("/login"))
                   );
   
           return http.build();
       }
   
       /**
        * 这个也是个Spring Security的过滤器链，用于Spring Security的身份认证。
        * @param http
        * @return
        * @throws Exception
        */
       @Bean
       @Order(2)
       public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
               throws Exception {
           http
                   .authorizeHttpRequests((authorize) -> authorize
                           .anyRequest().authenticated()
                   )
                   // Form login handles the redirect to the login page from the
                   // authorization server filter chain
                   .formLogin(Customizer.withDefaults());
   
           return http.build();
       }
   
       /**
        * 配置用户信息，或者配置用户数据来源，主要用于用户的检索。
        * @return
        */
       @Bean
       public UserDetailsService userDetailsService() {
           UserDetails userDetails = User.withDefaultPasswordEncoder()
                   .username("user")
                   .password("password")
                   .roles("USER")
                   .build();
   
           return new InMemoryUserDetailsManager(userDetails);
       }
   
       /**
        * oauth2 用于第三方认证，RegisteredClientRepository 主要用于管理第三方（每个第三方就是一个客户端）
        * @return
        */
       @Bean
       public RegisteredClientRepository registeredClientRepository() {
           RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                   .clientId("messaging-client")
                   .clientSecret("{noop}secret")
                   .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                   .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                   .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                   .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                   .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                   .redirectUri("http://127.0.0.1:8080/authorized")
                   .scope(OidcScopes.OPENID)
                   .scope("message.read")
                   .scope("message.write")
                   .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                   .build();
   
           return new InMemoryRegisteredClientRepository(registeredClient);
       }
   
       /**
        * 用于给access_token签名使用。
        * @return
        */
       @Bean
       public JWKSource<SecurityContext> jwkSource() {
           KeyPair keyPair = generateRsaKey();
           RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
           RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
           RSAKey rsaKey = new RSAKey.Builder(publicKey)
                   .privateKey(privateKey)
                   .keyID(UUID.randomUUID().toString())
                   .build();
           JWKSet jwkSet = new JWKSet(rsaKey);
           return new ImmutableJWKSet<>(jwkSet);
       }
   
       /**
        * 生成秘钥对，为jwkSource提供服务。
        * @return
        */
       private static KeyPair generateRsaKey() {
           KeyPair keyPair;
           try {
               KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
               keyPairGenerator.initialize(2048);
               keyPair = keyPairGenerator.generateKeyPair();
           } catch (Exception ex) {
               throw new IllegalStateException(ex);
           }
           return keyPair;
       }
   
       /**
        * 配置Authorization Server实例
        * @return
        */
       @Bean
       public ProviderSettings providerSettings() {
           return ProviderSettings.builder().build();
       }
   
   }
   ```

至此最小化项目完成，这就能够完成oauth2的授权。

### 测试

#### 授权码模式

启动项目，[点击访问](http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read&redirect_uri=http://127.0.0.1:8080/authorized)，如下图所示，账号为`user`，密码为`password`

> 需要注意的是`redirect_uri`必须是`RegisteredClient`实例设置的。

![授权码模式登录界面](./assets/image-20221014161922499.png)

输入用户名(`user`)密码(`password`）后

![授权界面](./assets/image-20221024160552339.png)

提交后，会自动跳转到`redirect_uri`地址，并且地址会紧跟着`code`。

![redirect_uri回调后携带code字段](./assets/image-20221024160649441.png)

返回的code是`oiaPrklBH-OmEhvpaaMplbldlreFJFnmCnhF6cL0SJAI-gYuo8N3W1hthoWGQi87ysexIxNTtzQ8baS1z3BwDOq55Tdda4_GtYsy9TJnBlCiQn3lLoGVsiH8-7Ul3UJy`

接下来需要使用这个`code`获取token（我用postman请求）

##### 获取Token

授权码获取token的请求地址是`oauth2/token`，`post`请求：

![请求体](./assets/image-20221024161258184.png)

上线这个三个参数是必须的，并且要跟代码中设置完全一直，另外获取`token`要传递`client_id`和`client_secret`参数，默认不支持使用表单传递，要通过`header`传递。比如在postman中

![通过header传递client_id和client_secret](./assets/image-20221024161759015.png)

其实上线的操作实际上就是在header中传递了一个header，key=Authorization， value是client_id:client_secret，然后使用base64加密的字符串,然后前面加上`Basic`(注意后面有空格)。对于我这个例子来说就是`Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=`

返回结果是：

```json
{
    "access_token": "eyJraWQiOiI5Y2UxZjNhMi04OTdlLTQyZGQtYTIwZC01NzU3OGY5NWMzZmUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY2NjU5OTQ0MCwic2NvcGUiOlsibWVzc2FnZS5yZWFkIl0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNjY2NTk5NzQwLCJpYXQiOjE2NjY1OTk0NDB9.MG3hO5s_x1J5YDqS9mpTm4RlQN0CKBWCZ6lbnOzalCoCFO7nITtSRbUdU3KPfsTZ5pqjlT8tsiyzre2xmlGRFPKSwKz6-miH0UHdndlIGevTh7_E-RlCydQ6MfIjsOvqNHbMyK_pIhANb8KLQEAzohhBFtZ4XurixZPBM_Q7-lJOXw_KGcaHnNA6N3yJCJPZmfX_e2B4Y6848CwmTTmPcOKWhdCwapJQN6LRA0XNjIUt4K2_-EXugx2k--DzLinQUgO3cbyf0hCucEZMiDJLKtJZaWvKgmryS8BjA4y8SrZO-aR--2G3lMwsCG6fOapdRIdXZxPyqSz5WuKU9ZwX2Q",
    "refresh_token": "O-G9EgyMQW4vgpxEElDNURer6Q4p1ZtRe1cgI9Kbc6k5UhZPKHAoVxirh9Chg9307XLCYlKIL9_E3JI3yl4bLU6iohY57LH-Q_Gfef3SnFP-T0wE1fSktDlrfNIpTCUP",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 300
}
```

##### 刷新Token

![刷新token请求方式](./assets/image-20221024162858034.png)

结果是：

```json
{
    "access_token": "eyJraWQiOiI5Y2UxZjNhMi04OTdlLTQyZGQtYTIwZC01NzU3OGY5NWMzZmUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY2NjYwMDAxMSwic2NvcGUiOlsibWVzc2FnZS5yZWFkIl0sImlzcyI6Imh0dHA6XC9cL2xvY2FsaG9zdDo4MDgwIiwiZXhwIjoxNjY2NjAwMzExLCJpYXQiOjE2NjY2MDAwMTF9.CAoHMeHWnQUk5DlGs-L93C8g2fPwnGLbbLiBtkFAfEDItT0UiZegWNYe-7nlNl4M8WdClZBEHW8KHLDOvbPjkaLr9a9ObRosiHu_DM9eIkKwptU0voYQJyfttrw2r6jeR1y9rek67YLetq4VzZ8lZOW006M8Zb6gV_-gTmuzhsgpNAtWKN0QKbexPZRtzG4qXr-td9qKlzFJdrYR3Ezwpvd42dT4TAxU3JGuITHglED-zq3D8HL7kPGwTTy0IONbl5boa9ID4qFHQiI7EQ7iV43tQJ1kBUiveIfjoBFHx1TjjyvTgdE09DyRtOMIe1ymdNEK8xRBNFgEuoiVoF_DuQ",
    "refresh_token": "O-G9EgyMQW4vgpxEElDNURer6Q4p1ZtRe1cgI9Kbc6k5UhZPKHAoVxirh9Chg9307XLCYlKIL9_E3JI3yl4bLU6iohY57LH-Q_Gfef3SnFP-T0wE1fSktDlrfNIpTCUP",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 300
}
```

#### 简化模式

在oauth2.1中被移除

#### 客户端模式

##### 获取Token

![客户端模式获取access_token](./assets/image-20221024163449048.png)

结果是：

```json
{
    "access_token": "eyJraWQiOiI5Y2UxZjNhMi04OTdlLTQyZGQtYTIwZC01NzU3OGY5NWMzZmUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZXNzYWdpbmctY2xpZW50IiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY2NjYwMDQyMywic2NvcGUiOlsib3BlbmlkIiwibWVzc2FnZS5yZWFkIiwibWVzc2FnZS53cml0ZSJdLCJpc3MiOiJodHRwOlwvXC9sb2NhbGhvc3Q6ODA4MCIsImV4cCI6MTY2NjYwMDcyMywiaWF0IjoxNjY2NjAwNDIzfQ.JhUVmVPj72XC6f8Q-xHt77Ch4YsLq5a49AB7l0zML-a0TxZ8vAtyTe5A96nc3vbg00rTWjpZ_NRgMWHzpkKOHWsWvqpImvPc_b3IB4NpyGGOwXVrFUmmVl1i12tB41F6SQAymlMQ8bA4ZxIdwdEbC5h1_BG0l2VIlhwVTkze2hM4RVRHrY6Yfk-FsMAc8cQIFWQihqkz3D8madyNlT7ux_b69mRWV0w4H0hAqwiSdxX4J6grKKk41BJZVifaPqvuU8TgvjQQYMzGuzx2L0ogxosNyEa2ojCbFRsd3gyFnJeNJ4XBntgxKaEz8wfFt5Kw-W69lQODSvpT3duQmAIKdg",
    "scope": "openid message.read message.write",
    "token_type": "Bearer",
    "expires_in": 300
}
```

客户端模式没有**刷新token**模式。

#### 密码模式

在oauth2.1中被移除

# 配置

## 默认配置

之前已经通过最小配置，完成了一个`Spring Authorization Server`项目，本章学习下关于配置的内容。

`Spring Authorization Server`还提供了一种实现最小配置的默认配置形式。就是通过`OAuth2AuthorizationServerConfiguration`这个类。

看下这个类的源码：

```java
/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configuration;

import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * {@link Configuration} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationServerConfigurer
 */
@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfiguration {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		applyDefaultSecurity(http);
		return http.build();
	}

	// @formatter:off
	public static void applyDefaultSecurity(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer<>();
		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();

		http
			.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests ->
				authorizeRequests.anyRequest().authenticated()
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			.apply(authorizationServerConfigurer);
	}
	// @formatter:on

	public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
		jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
		jwsAlgs.addAll(JWSAlgorithm.Family.EC);
		jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
		ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
		JWSKeySelector<SecurityContext> jwsKeySelector =
				new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);
		jwtProcessor.setJWSKeySelector(jwsKeySelector);
		// Override the default Nimbus claims set verifier as NimbusJwtDecoder handles it instead
		jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
		});
		return new NimbusJwtDecoder(jwtProcessor);
	}

	@Bean
	RegisterMissingBeanPostProcessor registerMissingBeanPostProcessor() {
		RegisterMissingBeanPostProcessor postProcessor = new RegisterMissingBeanPostProcessor();
		postProcessor.addBeanDefinition(ProviderSettings.class, () -> ProviderSettings.builder().build());
		return postProcessor;
	}
}
```

这里注入一个叫做`authorizationServerSecurityFilterChain`的bean，这跟我之前最小化项目时实现的基本是相同的。

有了这个bean，就会支持如下协议端点：

- [OAuth2 Authorization endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-authorization-endpoint)
- [OAuth2 Token endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-endpoint)
- [OAuth2 Token Introspection endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-introspection-endpoint)
- [OAuth2 Token Revocation endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-revocation-endpoint)
- [OAuth2 Authorization Server Metadata endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-authorization-server-metadata-endpoint)
- [JWK Set endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#jwk-set-endpoint)
- [OpenID Connect 1.0 Provider Configuration endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oidc-provider-configuration-endpoint)
- [OpenID Connect 1.0 UserInfo endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oidc-user-info-endpoint)

接来我我尝试使用`OAuth2AuthorizationServerConfiguration`这个类来实现一个`Authorization Server`。

> 本次我会将 Spring Security和Authorization Server的配置分开

Spring Security 使用 `SecurityConfig` 类，创建一个新的`Authorization Server`配置类 `AuthorizationServerConfig`。

`SecurityConfig`类配置如下：

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * 这个也是个Spring Security的过滤器链，用于Spring Security的身份认证。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * 配置用户信息，或者配置用户数据来源，主要用于用户的检索。
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }
}
```

代码如下：

```java
@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    /**
     * oauth2 用于第三方认证，RegisteredClientRepository 主要用于管理第三方（每个第三方就是一个客户端）
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 用于给access_token签名使用。
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成秘钥对，为jwkSource提供服务。
     *
     * @return
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
```

至此可以实现了`Authorization Server`。

## 测试客户端模式

![客户端模式调用](./assets/image-20221024164720507.png)

## 测试授权码模式

[点击访问](http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read&redirect_uri=http://127.0.0.1:8080/authorized)

![授权码模式](./assets/image-20221024165012833.png)

![获取Code](./assets/image-20221024165052652.png)

![授权码模式获取Token](./assets/image-20221024165217382.png)

# 存储配置

`Spring Authorization Server`默认是支持内存和JDBC两种存储模式的，内存模式只适合开发和简单的测试。接下来我们来实现JDBC存储方式。

修改步骤如下：

1. 引入JDBC相关依赖。
2. 创建数据库并初始化表，以及在`application.yaml`文件中配置数据库连接。
3. 修改`Spring Security`和`Spring authorization Server`的配置。
4. 初始化表数据
5. 测试服务

接下来我依次实现。

## 引入JDBC相关依赖

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>

<dependency>
    <groupId>mysql</groupId>
    <artifactId>mysql-connector-java</artifactId>
</dependency>
```

## 初始化表

创建数据库并初始化表，以及在`application.yaml`文件中配置数据库连接。

1. `oauth2_authorization_consent`
2. `oauth2_authorization`
3. `oauth2_registered_client`
4. `users`
5. `authorities`

```mysql
CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    attributes blob DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value blob DEFAULT NULL,
    authorization_code_issued_at timestamp DEFAULT NULL,
    authorization_code_expires_at timestamp DEFAULT NULL,
    authorization_code_metadata blob DEFAULT NULL,
    access_token_value blob DEFAULT NULL,
    access_token_issued_at timestamp DEFAULT NULL,
    access_token_expires_at timestamp DEFAULT NULL,
    access_token_metadata blob DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value blob DEFAULT NULL,
    oidc_id_token_issued_at timestamp DEFAULT NULL,
    oidc_id_token_expires_at timestamp DEFAULT NULL,
    oidc_id_token_metadata blob DEFAULT NULL,
    refresh_token_value blob DEFAULT NULL,
    refresh_token_issued_at timestamp DEFAULT NULL,
    refresh_token_expires_at timestamp DEFAULT NULL,
    refresh_token_metadata blob DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamp DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    PRIMARY KEY (id)
);

CREATE TABLE users ( 
	username varchar( 50 ) NOT NULL PRIMARY KEY, 
	PASSWORD varchar( 500 ) NOT NULL, 
	enabled boolean NOT NULL 
);

CREATE TABLE authorities (
	username VARCHAR ( 50 ) NOT NULL,
	authority VARCHAR ( 50 ) NOT NULL,
	CONSTRAINT ix_auth_username UNIQUE ( username, authority ),
	CONSTRAINT fk_authorities_users FOREIGN KEY ( username ) REFERENCES users ( username ) 
);
```

初始化表，建表语句在哪里？

`Spring Security`的建表语句在

```text
org/springframework/security/core/userdetails/jdbc/users.ddl
```

`Spring authorization Server`的建表文件在：

```text
org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql

org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql

org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql
```

都在jar包中，并且sql可能会有问题，请大家根据自己使用的数据库进行修改。

## 修改`yml`数据库连接信息

```yml
spring:
  datasource:
    type: com.zaxxer.hikari.HikariDataSource
    url: jdbc:mysql://192.168.38.150:3306/spring-authorization-server-example
    driver-class-name: com.mysql.cj.jdbc.Driver
    username: root
    password: root
```

请根据自己的情况进行修改。

## 修改配置信息

1. 修改`SecurityConfig`中的`UserDetailsService`bean。

   ```java
   	@Autowired
       private DataSource dataSource;
   
       @Bean
       public UserDetailsService userDetailsService() {
           return new JdbcUserDetailsManager(dataSource);
       }
   ```

2. `Spring Authorization Server`有三张表，对应的bean也要修改三处

   ```mysql
        @Autowired
       JdbcTemplate jdbcTemplate;
       
       @Bean
       public RegisteredClientRepository registeredClientRepository() {
           return new JdbcRegisteredClientRepository(jdbcTemplate);
       }
   
       @Bean
       public OAuth2AuthorizationService authorizationService() {
           return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository());
       }
   
       @Bean
       public OAuth2AuthorizationConsentService authorizationConsentService() {
           return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository());
       }
   ```

   上述三个类对应`Spring Authorization Server`的三个表。

## 初始化表数据

需要初始化三张表数据，分别是`users`,`authorities`, `oauth2_registered_client`

`users`,`authorities`需要通过`UserDetailsManager`类来实现，我暂时使用`junit Test`来实现。

```java
@SpringBootTest
class SpringAuthorizationServerExampleApplicationTests {

	/**
	 * 初始化客户端信息
	 */
	@Autowired
	private UserDetailsManager userDetailsManager;

	/**
	 * 创建用户信息
	 */
	@Test
	void testSaveUser() {
		UserDetails userDetails = User.builder().passwordEncoder(s -> "{bcrypt}" + new BCryptPasswordEncoder().encode(s))
				.username("user")
				.password("password")
				.roles("ADMIN")
				.build();
		userDetailsManager.createUser(userDetails);
	}
}
```

执行完毕后两个表的记录如下：

users：

| username | password                                                     | enabled |
| -------- | ------------------------------------------------------------ | ------- |
| `user`   | `{bcrypt}$2a$10$04v8GwjJLvol8g17v2Kse.ddR12/jTv8AvQRoxgXSaQyDfc5L.Zme` | `1`     |

authories:

| username | authority    |
| -------- | ------------ |
| `user`   | `ROLE_ADMIN` |

创建client信息

创建完成后，`oauth2_registered_client`表中的记录如下：

| id                                     | client_id          | client_id_issued_at   | client_secret                                                | client_secret_expires_at | client_name                            | client_authentication_methods | authorization_grant_types                             | redirect_uris                                                | scopes                              | client_settings                                              | token_settings                                               |
| -------------------------------------- | ------------------ | --------------------- | ------------------------------------------------------------ | ------------------------ | -------------------------------------- | ----------------------------- | ----------------------------------------------------- | ------------------------------------------------------------ | ----------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| `d526a138-66db-4c78-a286-e4b06b72d545` | `messaging-client` | `2022-10-24 18:09:43` | `{bcrypt}$2a$10$pYE0J8T4j0ZLGiQiFhUqMeNCFvPqy/flRnYg2oyyd1puypRun3t.a` |                          | `d526a138-66db-4c78-a286-e4b06b72d545` | `client_secret_basic`         | `refresh_token,client_credentials,authorization_code` | [http://127.0.0.1:8080/authorized](http://127.0.0.1:8080/authorized),[http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc](http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc) | `openid,message.read,message.write` | `{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":true}` | `{"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"],"settings.token.access-token-time-to-live":["java.time.Duration",300.000000000],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.core.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":["java.time.Duration",3600.000000000]}` |

## 测试

###  授权码模式

[点击访问](http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read&redirect_uri=http://127.0.0.1:8080/authorized)

输入用户名密码（`user`, `password`）后，**勾选scope**，确认后，通过**地址栏**能获得**code**。

