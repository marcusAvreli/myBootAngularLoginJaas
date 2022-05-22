package myBootAngularLoginJaas.controllers;


import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.validation.Valid;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import myBootAngularLoginJaas.persistence.model.Role;
import myBootAngularLoginJaas.persistence.model.User;
import myBootAngularLoginJaas.persistence.model.UserRoleType;
import myBootAngularLoginJaas.payload.request.LoginRequest;
import myBootAngularLoginJaas.payload.request.SignupRequest;
import myBootAngularLoginJaas.payload.resposne.JwtResponse;
import myBootAngularLoginJaas.payload.resposne.MessageResponse;
import myBootAngularLoginJaas.persistence.dao.RoleRepository;
import myBootAngularLoginJaas.persistence.dao.UserRepository;
import myBootAngularLoginJaas.security.jwt.JwtUtils;


@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	JwtUtils jwtUtils;
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		logger.info("[authenticateUser] 1");
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		logger.info("[authenticateUser] 2");
		SecurityContextHolder.getContext().setAuthentication(authentication);
		String jwt = jwtUtils.generateJwtToken(authentication);
		logger.info("[authenticateUser] 3");
		User userDetails = (User) authentication.getPrincipal();
		logger.info("[authenticateUser] 4");
		Set<Role> userRoles=userDetails.getRoles();
		List<String> roles = new ArrayList<String>();
		if(null != userRoles) {
		 Iterator<Role> it = userDetails.getRoles().iterator();
		 
	     while(it.hasNext()){
	        Role role=it.next();
	        roles.add(role.getRole())
;	     }
		}

		logger.info("[authenticateUser] 5"+roles);
		return ResponseEntity.ok(new JwtResponse(jwt, 
												 String.valueOf(userDetails.getId()), 
												 userDetails.getName(), 
												 userDetails.getEmail(), 
												 roles));
	}

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		logger.info("[registerUser]:1");
		/*if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity
					.badRequest()
					.body(new MessageResponse("Error: Email is already in use!"));
		}*/
		String userName=signUpRequest.getUsername();
		logger.info("[registerUser]:username ==>"+userName);
		// Create new user's account
		User user = new User(userName, 
							 signUpRequest.getEmail(),
							 encoder.encode(signUpRequest.getPassword()));
		logger.info("[registerUser]:3");
		Set<String> strRoles = signUpRequest.getRoles();
		logger.info("[registerUser]:Roles 1==> "+strRoles);
		Set<Role> roles = new HashSet<>();
		logger.info("[registerUser]:5");
		if (strRoles == null) {
			logger.info("[registerUser]:6");
			Role userRole = roleRepository.findByRole(UserRoleType.USER.toString());
			logger.info("[registerUser]: userRoles ==> "+userRole);
			roles.add(userRole);
		} else {
			logger.info("[registerUser]:8");
			strRoles.forEach(role -> {
				switch (role) {
				case "admin":
					Role adminRole = roleRepository.findByRole(UserRoleType.USER.toString());
						//	.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(adminRole);

					break;
				case "mod":
					Role modRole = roleRepository.findByRole(UserRoleType.USER.toString());
						//	.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(modRole);

					break;
				default:
					Role userRole = roleRepository.findByRole(UserRoleType.USER.toString());
							//.orElseThrow(() -> new RuntimeException("Error: Role is not found."));
					roles.add(userRole);
				}
			});
		}
		logger.info("[registerUser]:9");
		user.setRoles(roles);
		logger.info("[registerUser]:before save user.Name ==> "+user.getName());
		logger.info("[registerUser]:before save user Email==> "+user.getEmail());
		logger.info("[registerUser]:before save user Password==> "+user.getPassword());
		logger.info("[registerUser]:before save user Roles==> "+user.getRoles());
		userRepository.save(user);
		logger.info("[registerUser]:11");
		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}
}