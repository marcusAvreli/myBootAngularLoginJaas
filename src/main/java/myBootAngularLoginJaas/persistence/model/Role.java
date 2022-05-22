package myBootAngularLoginJaas.persistence.model;


import java.io.Serializable;


import javax.persistence.*;

@Entity
@Table(name = "role")
public class Role implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	
	/*public Role(int id, String role) {
		  this.id = id;
		  this.role = role;
		 }*/
	
	@Id
    @GeneratedValue(generator="loginPiIdGen",strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name="loginPiIdGen",sequenceName="loginPiId",allocationSize = 10)
    @Column(name = "role_id")
    private int id;
    @Column(name = "role")
    private String role;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        builder.append("Role [id=").append(id).append(", role=").append(role).append("]");
        return builder.toString();
    }
    @Override
	public boolean equals(Object obj) {
		if (obj == null)
			return false;
		if (this == obj)
			return true;
		if (!(obj instanceof Role))
			return false;
		Role other = (Role) obj;
		
		if (role != null && other.role != null && role.equals(other.role))
				return true;
		if (id==(other.id))
			return true;
		return false;
	}

}

