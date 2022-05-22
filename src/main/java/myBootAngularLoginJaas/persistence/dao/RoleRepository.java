package myBootAngularLoginJaas.persistence.dao;

import java.util.List;
import java.util.Set;


import myBootAngularLoginJaas.persistence.model.Role;

public interface RoleRepository  {
    Role findByRole(String role);
    Role findByRoleId(Integer id);
    Set<Role> findAll();
}