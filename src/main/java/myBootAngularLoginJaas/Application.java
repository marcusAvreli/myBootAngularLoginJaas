package myBootAngularLoginJaas;

import java.util.EnumSet;



import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;
import javax.servlet.SessionTrackingMode;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.context.request.RequestContextListener;






import myBootAngularLoginJaas.config.DatabaseConfig;
import myBootAngularLoginJaas.config.SecurityConfig;




/**
 * Hello world!
 *
 */
@Configuration

@EnableAutoConfiguration
@ComponentScan(basePackages = {"myBootAngularLogin"})
public class Application extends SpringBootServletInitializer{
	protected static Logger logger = LoggerFactory.getLogger(Application.class);
    public static void main( String[] args )
    {
        System.out.println( "Hello World!" );
    }
	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {

	
		logger.info("hello********************************");
		return application
				.sources(new Class[] { Application.class, SecurityConfig.class,DatabaseConfig.class });
	}
}