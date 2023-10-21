package com.ms.customer;

import com.ms.auth.role.Role;
import com.ms.auth.user.RoleRepository;
import com.ms.auth.user.User;
import com.ms.auth.user.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/public/user")
public class UserController {

    @Autowired
    RoleRepository roleRepository;
    @Autowired
    UserRepository userRepository;
    @PostMapping
    public ResponseEntity<User> saveUser(@RequestBody User user){
        user.setRoles(user.getRoles().stream().map( role -> roleRepository.findById(role.getId()).get()).collect(Collectors.toSet()));
        return new ResponseEntity<User>(userRepository.save(user), HttpStatus.OK);
    }

    @GetMapping("/roles")
    public ResponseEntity<List<Role>> getAllroles(){
        return new ResponseEntity<List<Role>>(roleRepository.findAll(), HttpStatus.OK);
    }
}
