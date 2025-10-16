package sw.skuniv.travelplanner.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import sw.skuniv.travelplanner.DI.dto.UserDTO;
import sw.skuniv.travelplanner.DI.entity.User;
import sw.skuniv.travelplanner.DI.repository.UserRepository;
import sw.skuniv.travelplanner.security.jwt.JwtUtil;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public UserDTO getCheckUserInfo(String jwtToken){
        String email = jwtUtil.getUserEmail(jwtToken);

        User user = userRepository.findByEmail(email)
                .orElseThrow(()-> new IllegalArgumentException("User not found with email: " + email));

        UserDTO info = new UserDTO();
        info.setId(user.getId());
        info.setEmail(user.getEmail());
        info.setName(user.getName());
        return info;

    }
}
