package it.unical.tickettwo.userservice.repository;

import it.unical.tickettwo.userservice.domain.UsersAccounts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UsersAccountsRepository extends JpaRepository<UsersAccounts, Long> {
    UsersAccounts findByUsername(String username);
}

