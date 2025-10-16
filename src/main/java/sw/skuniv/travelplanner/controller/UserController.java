package sw.skuniv.travelplanner.controller;

import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import sw.skuniv.travelplanner.DI.dto.UserDTO;
import sw.skuniv.travelplanner.DI.dto.UserDetailInfoDTO;
import sw.skuniv.travelplanner.DI.entity.User;
import sw.skuniv.travelplanner.DI.repository.UserRepository;
import sw.skuniv.travelplanner.security.jwt.JwtUtil;
import sw.skuniv.travelplanner.service.UserService;

import java.util.Optional;

@RequiredArgsConstructor
@RestController
public class UserController {
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final ModelMapper modelMapper;
    private final UserService userService;

    @PostMapping("/auth/additional-info")
    public ResponseEntity<Void> addAdditionalInfo(@RequestHeader("Authorization") String token, @RequestBody UserDetailInfoDTO userDetailInfoDTO) {
        try {
            String jwtToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            if (!jwtUtil.validateToken(jwtToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            Optional<User> optionalUser = userRepository.findByEmail(jwtUtil.getUserEmail(jwtToken));
            if (optionalUser.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }
            User user = optionalUser.get();
            user.setName(userDetailInfoDTO.getNickname());
            userRepository.save(user);
            return ResponseEntity.ok().build();


        } catch (Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/user/additionalInfo/check")
    public ResponseEntity<UserDTO> checkUserInfo(@RequestHeader("Authorization") String token){
        try {
            String jwtToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            if (!jwtUtil.validateToken(jwtToken)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
            UserDTO userDTO = userService.getCheckUserInfo(jwtToken);
            return ResponseEntity.ok(userDTO);

        } catch (Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
