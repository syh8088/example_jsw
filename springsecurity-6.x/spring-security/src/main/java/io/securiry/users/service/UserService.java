package io.securiry.users.service;

import io.securiry.users.repository.AccountRepository;
import io.securiry.users.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final AccountRepository accountRepository;

}
