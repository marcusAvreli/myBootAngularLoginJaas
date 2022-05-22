
package myBootAngularLoginJaas.persistence.dao;

import java.util.List;


import org.springframework.security.core.userdetails.UserDetails;


import myBootAngularLoginJaas.persistence.model.User;
//import simpleLogin.web.dto.UserDto;



public interface UserRepository {

	//User findByEmail(String email);
	User findById(int id);	
	List<User> getAllUsers();

	void save(User user);

	//void createUserAccount(UserDto accountDto);
	
	UserDetails loadUserByUsername(String username);
}