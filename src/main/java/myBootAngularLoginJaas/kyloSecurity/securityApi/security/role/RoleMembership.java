package myBootAngularLoginJaas.kyloSecurity.securityApi.security.role;



/*-
 * #%L
 * kylo-metadata-api
 * %%
 * Copyright (C) 2017 ThinkBig Analytics
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import java.security.Principal;
import java.util.Set;

import myBootAngularLoginJaas.kyloCommons.commonsSecurity.security.GroupPrincipal;
import myBootAngularLoginJaas.kyloCommons.commonsSecurity.security.UsernamePrincipal;

/**
 *
 */
public interface RoleMembership {

    SecurityRole getRole();
    
    Set<Principal> getMembers();
    
    void addMember(UsernamePrincipal principal);
    
    void addMember(GroupPrincipal principal);
    
    void setMemebers(UsernamePrincipal... principals);
    
    void setMemebers(GroupPrincipal... principals);
    
    void removeMember(UsernamePrincipal principal);
    
    void removeMember(GroupPrincipal principal);

    void removeAllMembers();
}
