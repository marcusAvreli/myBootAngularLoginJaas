package myBootAngularLoginJaas.persistence.model;


import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.SequenceGenerator;
import javax.persistence.Table;


import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import javax.persistence.JoinColumn;


import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


@Entity
@Table(name = "user")
//@javax.persistence.Entity; // add this <--
public class User implements UserDetails {

    @Id
    @GeneratedValue(generator="loginPiIdGen",strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(name="loginPiIdGen",sequenceName="loginPiId",allocationSize = 10)  
    private int id;
   // @Column(name = "email")
    //  @ValidEmail(message = "*Please provide an email")
    //  @NotEmpty(message = "*Please provide an email")
    private String email;
   // @Column(name = "password")
    //  @Length(min = 5, message = "*Your password must have at least 5 characters")
    //  @NotEmpty(message = "*Please provide your password")
    //  @Transient
    private String password;
    // @Column(name = "name")
    //  @NotEmpty(message = "*Please provide your name")
    private String name;
    //@Column(name = "last_name")
    //  @NotEmpty(message = "*Please provide your last name")
    private String lastName;
    //   @Column(name = "active")
    private int active;
    

    @ManyToMany(cascade = CascadeType.ALL,fetch = FetchType.EAGER)
    @JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();
   

    public User(String username, String email2, String encode) {

		this.name=username;
		this.email=email2;
		this.password=encode;
	}

	public User() {

		// TODO Auto-generated constructor stub
	}

	public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public int getActive() {
        return active;
    }

    public void setActive(int active) {
        this.active = active;
    }




	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUsername() {

		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isAccountNonExpired() {

		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {

		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {

		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {

		// TODO Auto-generated method stub
		return true;
	}
	 public Set<Role> getRoles() {

		return roles;
	}

	public void setRoles(Set<Role> roles) {

		this.roles = roles;
	}

}