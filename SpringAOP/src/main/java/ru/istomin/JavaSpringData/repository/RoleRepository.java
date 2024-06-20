package ru.istomin.JavaSpringData.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.istomin.JavaSpringData.model.Role;
import ru.istomin.JavaSpringData.model.User;

public interface RoleRepository extends JpaRepository<Role, Long> {
}