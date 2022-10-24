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

