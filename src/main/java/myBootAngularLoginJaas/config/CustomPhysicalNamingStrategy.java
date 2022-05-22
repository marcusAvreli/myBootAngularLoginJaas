package myBootAngularLoginJaas.config;


import org.hibernate.boot.model.naming.Identifier;
import org.hibernate.boot.model.naming.PhysicalNamingStrategyStandardImpl;
import org.hibernate.engine.jdbc.env.spi.JdbcEnvironment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



public class CustomPhysicalNamingStrategy
		extends PhysicalNamingStrategyStandardImpl  {

	
	private static final String TABLE_PREFIX = "APP_";


	private static final long serialVersionUID = 1L;
	
	public static final CustomPhysicalNamingStrategy STRATEGY_INSTANCE = new CustomPhysicalNamingStrategy();


	protected Logger logger = LoggerFactory.getLogger(CustomPhysicalNamingStrategy.class);


	public static final String CAMEL_CASE_REGEX = "([a-z]+)([A-Z]+)";


	public static final String SNAKE_CASE_PATTERN = "$1\\_$2";

	@Override
	public Identifier toPhysicalCatalogName(Identifier name, JdbcEnvironment context) {

		return formatIdentifier(super.toPhysicalCatalogName(name, context));
	}

	@Override
	public Identifier toPhysicalSchemaName(Identifier name, JdbcEnvironment context) {

		return formatIdentifier(super.toPhysicalSchemaName(name, context));
	}

	@Override
	public Identifier toPhysicalTableName(Identifier name, JdbcEnvironment context) {

		logger.info("simpleLogin:: SETTING PHYSICAL PREFIX");
		// https://stackoverflow.com/questions/4313095/jpa-hibernate-and-custom-table-prefixes
		Identifier newIdentifier = new Identifier(TABLE_PREFIX + name.getText().toUpperCase(), name.isQuoted());
		return super.toPhysicalTableName(newIdentifier, context);
	}

	@Override
	public Identifier toPhysicalSequenceName(Identifier name, JdbcEnvironment context) {

		return formatIdentifier(super.toPhysicalSequenceName(name, context));
	}

	@Override
	public Identifier toPhysicalColumnName(Identifier name, JdbcEnvironment context) {
		Identifier newIdentifier = new Identifier(name.getText().toUpperCase(), name.isQuoted());
		return super.toPhysicalTableName(newIdentifier, context);
	}

	private Identifier formatIdentifier(Identifier identifier) {

		if (identifier != null) {
			String name = identifier.getText();

			String formattedName = name.replaceAll(CAMEL_CASE_REGEX, SNAKE_CASE_PATTERN).toLowerCase();

			return !formattedName.equals(name) ? Identifier.toIdentifier(formattedName, identifier.isQuoted())
					: identifier;
		} else {
			return null;
		}

	}
}