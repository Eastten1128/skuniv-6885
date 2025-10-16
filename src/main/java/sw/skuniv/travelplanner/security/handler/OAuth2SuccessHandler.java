package sw.skuniv.travelplanner.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import sw.skuniv.travelplanner.DI.dto.UserDTO;
import sw.skuniv.travelplanner.DI.entity.User;
import sw.skuniv.travelplanner.DI.repository.UserRepository;
import sw.skuniv.travelplanner.security.jwt.JwtUtil;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
        String email = oAuth2User.getAttribute("email");

        Optional<User> optionalUser = userRepository.findByEmail(email);

        //기존 유저의 경우
        User user = optionalUser.get();
        UserDTO info = modelMapper.map(user, UserDTO.class);
        String token = jwtUtil.createAccessToken(info);
        response.sendRedirect("http://localhost:5173/main_a?token=" + token);


    }
}
