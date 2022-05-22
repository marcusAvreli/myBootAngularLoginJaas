package myBootAngularLoginJaas.config;

import java.util.HashMap;
import java.util.Map;


import javax.sql.DataSource;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.dao.annotation.PersistenceExceptionTranslationPostProcessor;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.Database;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.annotation.EnableTransactionManagement;


import myBootAngularLoginJaas.config.CustomPhysicalNamingStrategy;


//@Configuration
@EnableTransactionManagement
@EnableJpaRepositories("simpleLogin.persistence")
public class DatabaseConfig {
//https://github.com/deepak31205/E-Learning/blob/master/src/main/java/com/eLearning/configuration/DatabaseConfig.java
//https://github.com/dragontree101/spring-boot-demo/blob/master/spring-boot-hibernate/src/main/java/com/dragon/study/spring/boot/hibernate/HibernateConfiguration.java	
	protected Logger logger = LoggerFactory.getLogger(DatabaseConfig.class);
	@Autowired
	  private LocalContainerEntityManagerFactoryBean entityManagerFactoryBean;
	 @Bean
		public DataSource dataSource() {
			DriverManagerDataSource dataSource = new DriverManagerDataSource();
			dataSource.setDriverClassName("org.apache.derby.jdbc.ClientDriver");
			dataSource.setPassword("admin");
			dataSource.setUsername("admin");
			dataSource.setUrl("jdbc:derby://localhost:1527/C:/ApacheDerby/databases/MyDbTest2;create=true");
			return dataSource;
		}
	 @Bean
		public LocalContainerEntityManagerFactoryBean entityManagerFactory() {
			HibernateJpaVendorAdapter jpaVendorAdapter = new HibernateJpaVendorAdapter();

			jpaVendorAdapter.setDatabase(Database.DERBY);
			jpaVendorAdapter.setGenerateDdl(true);
			jpaVendorAdapter.setShowSql(true);

			Map<String, Object> jpaProperties = new HashMap<String,Object>();

			jpaProperties.put("hibernate.physical_naming_strategy", CustomPhysicalNamingStrategy.class.getName());
			jpaProperties.put("hbm2ddl.auto", "create");
			//jpaProperties.put("hibernate.implicit_naming_strategy", CustomPhysicalNamingStrategy.class.getName());
			LocalContainerEntityManagerFactoryBean entityManagerFactoryBean = new LocalContainerEntityManagerFactoryBean();
		
			entityManagerFactoryBean.setDataSource(dataSource());
			entityManagerFactoryBean.setPackagesToScan("simpleLogin");
			entityManagerFactoryBean.setMappingResources("orm.xml");
			entityManagerFactoryBean.setJpaVendorAdapter(jpaVendorAdapter);
			entityManagerFactoryBean.setJpaPropertyMap(jpaProperties);
			

			return entityManagerFactoryBean;
		}

	 @Bean
	  public JpaTransactionManager transactionManager() {
	    JpaTransactionManager transactionManager = new JpaTransactionManager();
	  transactionManager.setEntityManagerFactory( entityManagerFactory().getObject());
	  // transactionManager.setEntityManagerFactory(entityManagerFactoryBean.getObject());
	    return transactionManager;
	  }
	  

		@Bean
		public PersistenceExceptionTranslationPostProcessor exceptionTranslation() {
			return new PersistenceExceptionTranslationPostProcessor();
		}

}