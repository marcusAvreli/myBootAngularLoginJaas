package myBootAngularLoginJaas.controllers;

import java.util.List;


import javax.validation.constraints.DecimalMin;
import javax.validation.constraints.NotNull;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import myBootAngularLoginJaas.persistence.dao.UserRepository;
import myBootAngularLoginJaas.persistence.model.User;

@RestController

@RequestMapping("/api/rest")
public class IdentityController {
	@Autowired
	private final UserRepository userRepository;
	
	

	IdentityController(UserRepository userRepository) {
	    this.userRepository = userRepository;
	  }
	  @GetMapping("/identities")
	  List<User> all() {
	    return userRepository.getAllUsers();
	  }
	  @GetMapping("/identities/{id}")
	  public User findById(@PathVariable @NotNull @DecimalMin("0") int id) {
          return userRepository.findById(id);
	  }

}
