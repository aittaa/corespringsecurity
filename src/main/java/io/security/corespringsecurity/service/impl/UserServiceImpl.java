package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import io.security.corespringsecurity.service.UserService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;


@AllArgsConstructor

@Service("userService")
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;


    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
