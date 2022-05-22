
package myBootAngularLoginJaas.persistence.dao;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;


import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.Root;
import javax.transaction.Transactional;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;





import myBootAngularLoginJaas.persistence.dao.JpaResultHelper;
import myBootAngularLoginJaas.persistence.dao.UserRepository;
import myBootAngularLoginJaas.persistence.model.Role;
import myBootAngularLoginJaas.persistence.model.User;
//import simpleLogin.web.dto.UserDto



@Repository
public class UserRepositoryImpl implements UserRepository {

	private static final long serialVersionUID = 1L;

	@PersistenceContext
	private EntityManager entityManager;
    @Autowired
    private RoleRepository roleRepository;
	@Autowired
	private PasswordEncoder passwordEncoder;


	protected Logger logger = LoggerFactory.getLogger(UserRepositoryImpl.class);

	public UserRepositoryImpl() {

		logger.info("constructor");
	}
	@Transactional
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {

		logger.info("[loadUserByUsername]: processing username ==> "+username);
		if (username == null) {
			throw new UsernameNotFoundException("Usuário não encontrado.");
		}

		CriteriaBuilder cb = entityManager.getCriteriaBuilder();
		CriteriaQuery<User> cq = cb.createQuery(User.class);
		Root<User> user = cq.from(User.class);
		cq.where(cb.equal(user.get("name"), username));
		Query q = entityManager.createQuery(cq);

		logger.info("=====FIND BY USERNAME=====");
		User resultUser = (User) JpaResultHelper.getSingleResultOrNull(q);
		

		return  resultUser;
	}



	

	public User findByEmail(String email) {

		CriteriaBuilder cb = entityManager.getCriteriaBuilder();
		CriteriaQuery<User> cq = cb.createQuery(User.class);
		Root<User> user = cq.from(User.class);
		cq.where(cb.equal(user.get("email"), email));
		Query q = entityManager.createQuery(cq);

		logger.info("=====FIND BY EMAIL=====");
		User resultUser = (User) JpaResultHelper.getSingleResultOrNull(q);

		return resultUser;
	}
	public User findById(int id) {

		CriteriaBuilder cb = entityManager.getCriteriaBuilder();
		CriteriaQuery<User> cq = cb.createQuery(User.class);
		Root<User> user = cq.from(User.class);
		cq.where(cb.equal(user.get("id"), id));
		Query q = entityManager.createQuery(cq);

		logger.info("=====FIND BY ID=====");
		User resultUser = (User) JpaResultHelper.getSingleResultOrNull(q);

		return resultUser;
	}

	/*@Transactional
	@Override

	public void createUserAccount(UserDto accountDto) {
		logger.info("==>createUserAccount_called<==");
		final User user = new User();
		user.setName(accountDto.getFirstName());
		user.setLastName(accountDto.getLastName());
		user.setEmail(accountDto.getEmail());
		user.setPassword(passwordEncoder.encode(accountDto.getPassword()));
		//user.setRoles(roles);
		user.setActive(1);
		logger.info("==>createUserAccount_account role<=="+accountDto.getRole());
		 Role userRole = roleRepository.findByRoleId(accountDto.getRole());
		// user.setRoles(new HashSet<Role>(Arrays.asList(userRole)));
		 user.setRoles((Arrays.asList(userRole)));
		 logger.info("==>createUserAccount_finished<==");
		entityManager.persist(user);
	}*/

	@Transactional
	public void save(User user) {

		logger.info("custom saving user 1");
		entityManager.persist(user);

		//return true;

	}




	@Override
	public List<User> getAllUsers() {
		logger.info("==>get_all_users_started<==");
		CriteriaBuilder cb = entityManager.getCriteriaBuilder();
	    CriteriaQuery<User> cq = cb.createQuery(User.class);
	    Root<User> rootEntry = cq.from(User.class);
	    CriteriaQuery<User> all = cq.select(rootEntry);
	 
	    TypedQuery<User> allQuery = entityManager.createQuery(all);
	    List<User> users=allQuery.getResultList();
	    logger.info("result list ==>"+users);
	    logger.info("==>get_all_users_finished<==");
		return users;
	}

}
