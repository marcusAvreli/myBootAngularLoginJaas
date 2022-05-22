package myBootAngularLoginJaas.persistence.dao;

import java.util.List;


import javax.persistence.NonUniqueResultException;
import javax.persistence.Query;

public class JpaResultHelper {

    public static Object getSingleResultOrNull(Query query) {
        Object result = null;
        List results = query.getResultList();
        if (results.isEmpty()) {
            result = null;
        } else if (results.size() == 1) {
            result = results.get(0);
        } else {
            throw new NonUniqueResultException();
        }
        return result;
    }
}