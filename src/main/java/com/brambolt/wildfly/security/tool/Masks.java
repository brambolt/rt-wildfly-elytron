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
 *
 * This code is based on
 *   https://github.com/wildfly-security/wildfly-elytron-tool/blob/master/src/main/java/org/wildfly/security/tool/MaskCommand.java
 */

package com.brambolt.wildfly.security.tool;

import org.wildfly.security.tool.ElytronToolMessages;
import org.wildfly.security.util.PasswordBasedEncryptionUtil;

import java.security.GeneralSecurityException;

public class Masks {

    public static final String MASK_PREFIX = "MASK-";

    public enum MODE { ENCRYPT, DECRYPT }

    public static String computeMasked(String secret, String salt, int iteration) throws GeneralSecurityException {
        PasswordBasedEncryptionUtil encryptUtil = createUtil(salt, iteration, MODE.ENCRYPT);
        return MASK_PREFIX + encryptUtil.encryptAndEncode(secret.toCharArray()) + ";" + salt + ";" + iteration;
    }

    public static char[] decryptMasked(String maskedPassword) throws GeneralSecurityException {
        int maskLength = MASK_PREFIX.length();
        if (null == maskedPassword || maskedPassword.length() <= maskLength)
            throw ElytronToolMessages.msg.wrongMaskedPasswordFormat();
        String[] parsed = maskedPassword.substring(maskLength).split(";");
        if (parsed.length != 3)
            throw ElytronToolMessages.msg.wrongMaskedPasswordFormat();
        String encoded = parsed[0];
        String salt = parsed[1];
        int iteration = Integer.parseInt(parsed[2]);
        PasswordBasedEncryptionUtil util = createUtil(salt, iteration, MODE.DECRYPT);
        return util.decodeAndDecrypt(encoded);
    }

    public static PasswordBasedEncryptionUtil
    createUtil(String salt, int iteration, MODE mode)
        throws GeneralSecurityException {
        PasswordBasedEncryptionUtil.Builder builder = new PasswordBasedEncryptionUtil.Builder()
            .picketBoxCompatibility()
            .salt(salt)
            .iteration(iteration);
        return (MODE.ENCRYPT.equals(mode))
            ? builder.encryptMode().build()
            : builder.decryptMode().build();
    }
}
