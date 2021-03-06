package myBootAngularLoginJaas.kyloMetadata.metadataModeshape.support;

import myBootAngularLoginJaas.kyloMetadata.metadataApi.MetadataException;

/*-
 * #%L
 * kylo-metadata-modeshape
 * %%
 * Copyright (C) 2017 - 2018 ThinkBig Analytics, a Teradata Company
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

import myBootAngularLoginJaas.kyloMetadata.metadataModeshape.MetadataRepositoryException;

import javax.jcr.lock.LockException;

/**
 *
 */
public class MetadataLockException extends MetadataException {

    private static final long serialVersionUID = 1L;

    public MetadataLockException(LockException e) {
        super(e);
    }
}
