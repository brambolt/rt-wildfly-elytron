/*
 * Copyright 2020 Brambolt ehf.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.brambolt.wildfly.security.credential.store;

import org.wildfly.security.auth.server.IdentityCredentials;
import org.wildfly.security.credential.PasswordCredential;
import org.wildfly.security.credential.store.CredentialStore;
import org.wildfly.security.credential.store.CredentialStoreException;
import org.wildfly.security.credential.store.impl.KeyStoreCredentialStore;
import org.wildfly.security.password.Password;
import org.wildfly.security.password.interfaces.ClearPassword;

import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class CredentialStores {

    public static final String DEFAULT_CREDENTIAL_STORE_TYPE = KeyStoreCredentialStore.class.getSimpleName();

    public static final String DEFAULT_KEY_STORE_TYPE = "JCEKS";

    public static CredentialStore create(File location, String password)
        throws CredentialStoreException, NoSuchAlgorithmException {
        return create(DEFAULT_CREDENTIAL_STORE_TYPE, location, password, false);
    }

    public static CredentialStore create(File location, String password, Boolean isNew)
        throws CredentialStoreException, NoSuchAlgorithmException {
        return create(DEFAULT_CREDENTIAL_STORE_TYPE, location, password, isNew);
    }

    public static CredentialStore create(String type, File location, String password)
        throws CredentialStoreException, NoSuchAlgorithmException {
        return create(type, location, password, false);
    }

    public static CredentialStore create(String type, File location, String password, Boolean isNew)
        throws CredentialStoreException, NoSuchAlgorithmException {
        return create(type, createProperties(location, isNew), createProtection(password));
    }

    public static CredentialStore create(
        String type,
        Map<String, String> properties,
        CredentialStore.CredentialSourceProtectionParameter protection)
        throws CredentialStoreException, NoSuchAlgorithmException {
        CredentialStore store = CredentialStore.getInstance(type);
        store.initialize(properties, protection);
        return store;
    }

    public static Map<String, String> createProperties(File location, Boolean isNew) {
        Map<String, String> properties = new HashMap<>();
        properties.put("create", isNew.toString());
        properties.put("keyStoreType", DEFAULT_KEY_STORE_TYPE);
        properties.put("location", location.getAbsolutePath());
        properties.put("modifiable", Boolean.TRUE.toString());
        return properties;
    }

    public static CredentialStore.CredentialSourceProtectionParameter createProtection(String password) {
        return new CredentialStore.CredentialSourceProtectionParameter(
            IdentityCredentials.NONE.withCredential(
                createClearPasswordCredential(password)));
    }

    /**
     * Creates a password credential object from the parameter secret. The secret
     * must be cleartext (unmasked).
     *
     * @param secret The secret to create the password credential for
     * @return A password credential object holding the secret
     */
    public static PasswordCredential createClearPasswordCredential(String secret) {
        return createClearPasswordCredential(secret.toCharArray());
    }

    /**
     * Creates a password credential object from the parameter secret. The secret
     * must be cleartext (unmasked).
     *
     * @param secret The secret to create the password credential for
     * @return A password credential object holding the secret
     */
    public static PasswordCredential createClearPasswordCredential(char[] secret) {
        return new PasswordCredential(createClearPassword(secret));
    }

    public static ClearPassword createClearPassword(String secret) {
        return createClearPassword(secret.toCharArray());
    }

    public static ClearPassword createClearPassword(char[] secret) {
        return ClearPassword.createRaw(ClearPassword.ALGORITHM_CLEAR, secret);
    }

    public static void storeClearPassword(CredentialStore store, String alias, String secret)
        throws CredentialStoreException {
        storeClearPassword(store, alias, secret.toCharArray());
    }

    public static void storeClearPassword(CredentialStore store, String alias, char[] secret)
        throws CredentialStoreException {
        store.store(alias, createClearPasswordCredential(secret));
    }

    public static char[] retrieveClearPassword(CredentialStore store, String alias)
        throws CredentialStoreException {
        PasswordCredential credential = store.retrieve(alias, PasswordCredential.class);
        if (null == credential)
            return null;
        Password password = credential.getPassword();
        if (null == password)
            return null;
        return ((ClearPassword) password).getPassword();
    }
}
