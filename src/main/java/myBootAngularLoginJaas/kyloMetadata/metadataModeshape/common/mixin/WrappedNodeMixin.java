package myBootAngularLoginJaas.kyloMetadata.metadataModeshape.common.mixin;



import java.io.UnsupportedEncodingException;

/*-
 * #%L
 * kylo-metadata-modeshape
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

import java.lang.reflect.InvocationTargetException;
import java.security.AccessControlException;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.jcr.AccessDeniedException;
import javax.jcr.Node;
import javax.jcr.RepositoryException;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.ConstructorUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import myBootAngularLoginJaas.kyloMetadata.metadataApi.Propertied;
import myBootAngularLoginJaas.kyloMetadata.metadataModeshape.MetadataRepositoryException;
import myBootAngularLoginJaas.kyloMetadata.metadataModeshape.UnknownPropertyException;
import myBootAngularLoginJaas.kyloMetadata.metadataModeshape.common.JcrObject;
import myBootAngularLoginJaas.kyloMetadata.metadataModeshape.support.JcrPropertyUtil;
import myBootAngularLoginJaas.kyloMetadata.metadataModeshape.support.JcrUtil;

/**
 * 
 * TODO: Refactor hierarchy of JcrObject so that JCR-based entity objects implement 
 * this interface (or one or more mixin subtypes) instead.
 */
public interface WrappedNodeMixin extends Propertied {
    
    Logger log = LoggerFactory.getLogger(WrappedNodeMixin.class);

    Node getNode();

    default String getTypeName() {
        try {
            return getNode().getPrimaryNodeType().getName();
        } catch (RepositoryException e) {
            throw new MetadataRepositoryException("Failed to retrieve the entity type name", e);
        }
    }

    default boolean isNew() {
        return getNode().isNew();
    }

    default boolean isModified() {
        return getNode().isModified();
    }

    default void refresh(boolean keepChanges) {
        try {
            getNode().refresh(keepChanges);
        } catch (RepositoryException e) {
            throw new MetadataRepositoryException("Unable to refresh Node. ", e);
        }
    }

    default String getPath() {
        try {
            return getNode().getPath();
        } catch (RepositoryException e) {
            throw new MetadataRepositoryException("Unable to get the Path", e);
        }
    }

    default String getNodeName() {
        try {
            return getNode().getName();
        } catch (RepositoryException e) {
            throw new MetadataRepositoryException("Unable to get the Node Name", e);
        }
    }

    default void remove() {
        try {
            getNode().remove();
        } catch (RepositoryException e) {
            throw new MetadataRepositoryException("Unable to remove the node", e);
        }
    }

    default boolean isLive() {
        if (getNode() != null) {
            try {
                if (getNode().getSession() != null) {
                    return getNode().getSession().isLive();
                }
            } catch (RepositoryException e) {

            }
        }
        return false;
    }

    default Map<String, Object> getProperties() {
        return JcrPropertyUtil.getProperties(getNode());
    }

    default void setProperties(Map<String, Object> properties) {
        //add the properties as attrs
        for (Map.Entry<String, Object> entry : properties.entrySet()) {
            setProperty(entry.getKey(), entry.getValue());
        }
    }

    default <T> T getProperty(String name) {
        return JcrPropertyUtil.getProperty(getNode(), name);
    }

    default <T> Set<T> getPropertyAsSet(String name, Class<T> objectType) {
        Object o = null;
        try {
            o = JcrPropertyUtil.getProperty(getNode(), name);
        } catch (UnknownPropertyException e) {

        }
        if (o != null) {
            if (o instanceof Collection) {
                //convert the objects to the correct type if needed
                if (JcrObject.class.isAssignableFrom(objectType)) {
                    Set<T> objects = new HashSet<>();
                    for (Object collectionObj : (Collection) o) {
                        T obj = null;
                        if (collectionObj instanceof Node) {

                            try {
                                obj = ConstructorUtils.invokeConstructor(objectType, (Node) collectionObj);
                            } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | InstantiationException e) {
                                obj = (T) collectionObj;
                            }

                        } else {
                            obj = (T) collectionObj;
                        }
                        objects.add(obj);
                    }
                    return objects;
                } else {
                    return new HashSet<T>((Collection) o);
                }
            } else {
                Set<T> set = new HashSet<>();
                if (JcrObject.class.isAssignableFrom(objectType) && o instanceof Node) {
                    T obj = null;
                    try {
                        obj = ConstructorUtils.invokeConstructor(objectType, (Node) o);
                        set.add((T) obj);
                    } catch (NoSuchMethodException | IllegalAccessException | InvocationTargetException | InstantiationException e) {

                    }
                    set.add(obj);
                } else {
                    set.add((T) o);
                }
                return set;
            }
        }
        return new HashSet<T>();
    }

    default boolean hasProperty(String name) {
        try {
            return getNode().hasProperty(name);
        } catch (AccessDeniedException e) {
            log.debug("Unable to access property: \"{}\" from node: {}", name, getNode(), e);
            return false;
        } catch (AccessControlException e) {
            return false;
        } catch (RepositoryException e) {
            throw new MetadataRepositoryException("Unable to check Property " + name);
        }
    }

    @SuppressWarnings("unchecked")
    default <T> T getProperty(String name, T defValue) {
        if (hasProperty(name)) {
            return getProperty(name, (Class<T>) defValue.getClass(), defValue);
        } else {
            return defValue;
        }
    }

    default <T> T getProperty(String name, Class<T> type) {
        if (type == null) {
            // The null value for type was meant to be the default value but wasn't cast as one.
            return JcrPropertyUtil.getProperty(getNode(), name, true);
        } else {
            return getProperty(name, type, null);
        }
    }

    default <T> T getProperty(String name, Class<T> type, T defaultValue) {
        return getPropertyFromNode(getNode(), name, type, defaultValue);
    }

    default <T> T getPropertyFromNode(Node node, String name, Class<T> type, T defaultValue) {
        Object o = JcrPropertyUtil.getProperty(node, name, defaultValue);
        
        if (o == null) {
            return null;
        }
        if (type.isEnum()) {
            String savedType = o.toString();
            if (StringUtils.isNotBlank(savedType)) {
                Class<? extends Enum> x = (Class<? extends Enum>) type;
                return (T) Enum.valueOf(x, savedType);
            }
        }
        if (!o.getClass().isAssignableFrom(type)) {
            // conversion for Node to JcrObject
            if (o instanceof Node && JcrObject.class.isAssignableFrom(type)) {
                return JcrUtil.constructNodeObject((Node) o, type, null);
            }
            // conversion for byte[] to String
            if (o instanceof byte[] && String.class.equals(type)) {
                try {
                    return (T) new String((byte[]) o, "UTF-8");
                } catch (final UnsupportedEncodingException e) {
                    throw new MetadataRepositoryException("Unable to decode String property '" + name + "'", e);
                }
            }
            // unable to convert
            final String safeName = name.toLowerCase().contains("password") ? "UNKNOWN" : name;
            throw new MetadataRepositoryException("Unable to convert Property " + safeName + " to type " + type);
        } else {
            return (T) o;
        }
    }

    default void setProperty(String name, Object value) {
        JcrPropertyUtil.setProperty(getNode(), name, value);
    }

    default void removeProperty(String key) {
        setProperty(key, null);
    }

    /**
     * Merges any new properties in with the other Extra Properties
     */
    @Override
    default Map<String, Object> mergeProperties(Map<String, Object> props) {
        Map<String, Object> newProps = new HashMap<>();
        Map<String, Object> origProps = getProperties();
        if (origProps != null) {
            newProps.putAll(origProps);
        }
        if (props != null) {
            newProps.putAll(props);
        }
        
        setProperties(newProps);
        return newProps;
    }

}
