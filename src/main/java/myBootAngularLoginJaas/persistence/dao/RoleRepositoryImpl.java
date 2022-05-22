
package myBootAngularLoginJaas.persistence.dao;

import java.util.HashSet;
import java.util.List;
import java.util.Set;


import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;
import javax.persistence.criteria.CriteriaBuilder;
import javax.persistence.criteria.CriteriaQuery;
import javax.persistence.criteria.ParameterExpression;
import javax.persistence.criteria.Root;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import myBootAngularLoginJaas.persistence.dao.RoleRepository;
import myBootAngularLoginJaas.persistence.model.Role;



@Service("roleRepositoryImpl")
@Transactional
// @Repository("roleRepositoryImpl")
public class RoleRepositoryImpl implements RoleRepository {

	private static final long serialVersionUID = 1L;


	protected Logger logger = LoggerFactory.getLogger(RoleRepositoryImpl.class);


	@PersistenceContext
	private EntityManager entityManager;

	public RoleRepositoryImpl() {

		logger.info("::CONSTRUCTOR::");
	}

	public Set<Role> findAll() {

		logger.info("==>find_all_roles_called<==");
		CriteriaBuilder cb = entityManager.getCriteriaBuilder();
		CriteriaQuery<Role> cq = cb.createQuery(Role.class);
		Root<Role> root = cq.from(Role.class);
		CriteriaQuery<Role> all = cq.select(root);
		TypedQuery<Role> allQuery = entityManager.createQuery(all);

		List<Role> rolesList = allQuery.getResultList();
		Set<Role> roles = new HashSet<Role>(rolesList);

		logger.info("==>find_all_roles_finished<==");
		return roles;
	}

	public Role findByRoleId(Integer id) {

		logger.info("==>find_role_by_id_called<==");
		CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		CriteriaQuery<Role> criteriaQuery = builder.createQuery(Role.class);
		Root<Role> root = criteriaQuery.from(Role.class);
		ParameterExpression<Integer> parameter = builder.parameter(Integer.class);

		criteriaQuery.select(root).where(builder.equal(root.get("id"), parameter));
		Query query = entityManager.createQuery(criteriaQuery);
		query.setParameter(parameter, id);
		Role resultRole = (Role) JpaResultHelper.getSingleResultOrNull(query);
		logger.info("==>find_role_by_id_finished<==");
		return resultRole;
	}

	public Role findByRole(String role) {

		logger.info("==>find_role_by_name_called<==");
		CriteriaBuilder cb = entityManager.getCriteriaBuilder();
		CriteriaQuery<Role> cq = cb.createQuery(Role.class);
		Root<Role> roleObj = cq.from(Role.class);
		cq.where(cb.equal(roleObj.get("role"), role));
		Query q = entityManager.createQuery(cq);

		Role resultRole = (Role) JpaResultHelper.getSingleResultOrNull(q);
		logger.info("==>find_role_by_name_finished<==");
		return resultRole;
	}

}