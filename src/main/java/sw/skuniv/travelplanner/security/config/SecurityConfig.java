package sw.skuniv.travelplanner.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import sw.skuniv.travelplanner.security.handler.OAuth2FailureHandler;
import sw.skuniv.travelplanner.security.handler.OAuth2SuccessHandler;
import sw.skuniv.travelplanner.security.jwt.JwtAuthFilter;
import sw.skuniv.travelplanner.security.jwt.JwtUtil;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService;
    private final JwtAuthFilter jwtAuthFilter;

    private final JwtUtil jwtUtil;

    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final OAuth2FailureHandler oAuth2FailureHandler;


    private static final String[] permit_userController_list = {

    };

    private static final String[] authenticate_userController_list = {
            "/auth/additional-info","/user/additionalInfo/check"
    };

    private static final String[] permit_albumController_list = {
            "/featuredToday","/top10Album","/album/detail","/album/image/{filename}","/album/search"
    };

    private static final String[] authenticate_albumController_list = {
            "/albumRegist","/preferenceGenre"
    };

    private static final String[] permit_reviewController_list = {
            "/reviews","/qualityReviewerAward"
    };

    private static final String[] authenticate_reviewController_list = {
            "/review/submit","/reviews/{id}/like"
    };

    private static final String[] permit_ratingController_list = {

    };

    private static final String[] authenticate_ratingController_list = {
            "/rating"
    };

    private static final String[] permit_security_list = {
            "/", "/login/*","/main_b","/main_a/*"
    };

    private static final String[] authenticate_security_list = {
            "/security/autoLogin", "/security/logout"
    };


    @Bean
    public WebSecurityCustomizer configure(){
        return (web -> web.ignoring()
                //spring security가 지정된 경로를 무시하도록 설정
                //.requestMatchers("home"));
                .requestMatchers("static/**")); //static/**의 경우 정적 리소스 폴더(예: CSS, JS 파일등)로 들어오는 모든 요청 무시
    }

    //SecurityFilterChain의 requestMatcheres의 경우 특정 경로에 대해 인증 및 권한 검사 설정
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //csrf 보안 비활성화
        http.csrf((csrf) -> csrf.disable());

        http.cors(withDefaults());

        //FormLogin, BasicHttp 비활성화
        http.formLogin((form) -> form.disable());
        http.httpBasic(AbstractHttpConfigurer:: disable);


        //JwtAuthFilter를 UsernamePasswordAuthenticationFilter 앞에 추가
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);


        //권한 규칙 작성
        http.authorizeHttpRequests(auth -> auth

                //권한이 필요하지 않은 경로
                .requestMatchers(permit_userController_list).permitAll()
                .requestMatchers(permit_albumController_list).permitAll()
                .requestMatchers(permit_reviewController_list).permitAll()
                .requestMatchers(permit_ratingController_list).permitAll()
                .requestMatchers(permit_security_list).permitAll()

                //권한이 필요한 경로
                .requestMatchers(authenticate_userController_list).authenticated()
                .requestMatchers(authenticate_albumController_list).authenticated()
                .requestMatchers(authenticate_reviewController_list).authenticated()
                .requestMatchers(authenticate_ratingController_list).authenticated()
                .requestMatchers(authenticate_security_list).authenticated()

                .anyRequest().authenticated()
        );

        http.oauth2Login(oauth -> oauth
                .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                .successHandler(oAuth2SuccessHandler)
                .failureHandler(oAuth2FailureHandler)
        );

        return http.build();
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:5173")
                        .allowedMethods("*")
                        .allowedHeaders("*")
                        .allowCredentials(true);
            }
        };
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:5173"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }



    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
