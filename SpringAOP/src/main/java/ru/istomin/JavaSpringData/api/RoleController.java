package ru.istomin.JavaSpringData.api;

import io.swagger.v3.oas.annotations.Operation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ru.istomin.JavaSpringData.model.Role;
import ru.istomin.JavaSpringData.model.User;
import ru.istomin.JavaSpringData.service.RoleService;
import ru.istomin.JavaSpringData.service.UserService;

import java.util.List;

@RestController
@RequestMapping("/roles")
public class RoleController {
    private final RoleService roleService;

    @Autowired
    public RoleController(RoleService roleService) {
        this.roleService = roleService;
    }


    //получить список всех ролей
    @GetMapping
    public ResponseEntity<List<Role>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles()); }

    // создание роли
    @PostMapping
    public ResponseEntity<Role> addRole(@RequestBody Role role){
        return new ResponseEntity<>(roleService.addRole(role), HttpStatus.CREATED);
    }
}
