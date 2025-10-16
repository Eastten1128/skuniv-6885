package sw.skuniv.travelplanner.security.config;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import sw.skuniv.travelplanner.DI.entity.User;
import sw.skuniv.travelplanner.DI.repository.UserRepository;
import sw.skuniv.travelplanner.security.jwt.JwtUtil;

import java.util.Collections;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    private final ModelMapper modelMapper;


    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User googleUser = new DefaultOAuth2UserService().loadUser(request);
        String email = googleUser.getAttribute("email");

        User user;
        Optional<User> optionalUser = userRepository.findByEmail(email);

        if (optionalUser.isEmpty()) {
            user = userRepository.save(User.builder()
                    .email(email)
                    .role(User.Role.ROLE_USER)
                    .build());
        } else {
            user = optionalUser.get();
        }

        return new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRole().name())),
                googleUser.getAttributes(),
                "email"
        );


    }
}
