package sw.skuniv.travelplanner.DI.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import sw.skuniv.travelplanner.DI.entity.User;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    User getByEmail(String email);

    User findUserByEmail(String email);

    Boolean existsByEmail(String email);

    List<User> findByEmailContainingAndEmailNot(String keyword, String userEmail);

    void deleteByEmail(String email);
}
