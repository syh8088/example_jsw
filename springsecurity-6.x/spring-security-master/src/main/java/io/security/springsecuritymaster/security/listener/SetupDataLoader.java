package io.security.springsecuritymaster.security.listener;

import io.security.springsecuritymaster.admin.repository.RoleRepository;
import io.security.springsecuritymaster.domain.entity.Account;
import io.security.springsecuritymaster.domain.entity.Role;
import io.security.springsecuritymaster.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class SetupDataLoader implements ApplicationListener<ContextRefreshedEvent> {
    private boolean alreadySetup = false;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    @Transactional
    public void onApplicationEvent(final ContextRefreshedEvent event) {
        if (alreadySetup) {
            return;
        }
        setupData();
        alreadySetup = true;
    }

    private void setupData() {

        HashSet<Role> adminRoles = new HashSet<>();
        Role adminRole = createRoleIfNotFound("ROLE_ADMIN", "관리자 권한");
        adminRoles.add(adminRole);

        HashSet<Role> managerRoles = new HashSet<>();
        Role managerRole = createRoleIfNotFound("ROLE_MANAGER", "사용자 권한");
        managerRoles.add(managerRole);

        HashSet<Role> userRoles = new HashSet<>();
        Role userRole = createRoleIfNotFound("ROLE_USER", "사용자 권한");
        userRoles.add(userRole);

        createUserIfNotFound("admin", "admin@admin.com", "1234", adminRoles);
        createUserIfNotFound("manager", "manager@manager.com", "1234", managerRoles);
        createUserIfNotFound("user", "user@user.com", "1234", userRoles);
    }

    public Role createRoleIfNotFound(String roleName, String roleDesc) {
        Role role = roleRepository.findByRoleName(roleName);

        if (role == null) {
            role = Role.builder()
                    .roleName(roleName)
                    .roleDesc(roleDesc)
                    .isExpression("N")
                    .build();
        }
        return roleRepository.save(role);
    }

    public void createUserIfNotFound(final String userName, final String email, final String password, Set<Role> roleSet) {

        Account account = userRepository.findByUsername(userName);

        if (account == null) {
            account = Account.builder()
                    .username(userName)
                    .password(passwordEncoder.encode(password))
                    .userRoles(roleSet)
                    .build();
        }

        userRepository.save(account);
    }

}