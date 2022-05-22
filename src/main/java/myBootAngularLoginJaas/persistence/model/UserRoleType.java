package myBootAngularLoginJaas.persistence.model;


public enum UserRoleType {
	USER("USER"),
	DBA("DBA"),
	ADMIN("ADMIN");
	
	String userRoleType;
	
	private UserRoleType(String userRoleType){
		this.userRoleType = userRoleType;
	}
	
	public String getUserProfileType(){
		return userRoleType;
	}
}
