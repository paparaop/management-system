package com.ms.security.repository;

import com.ms.security.entities.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@RepositoryRestResource(collectionResourceRel = "user_info", path = "user_info")
public interface UserRepository extends JpaRepository<UserInfo, Integer> {
    // Since email is unique, we'll find users by email
    Optional<UserInfo> findByEmail(String email);
}
