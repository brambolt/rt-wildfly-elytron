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

package com.brambolt.wildfly.security.credential.store

import org.junit.Rule
import org.junit.rules.TemporaryFolder
import org.wildfly.security.WildFlyElytronProvider
import spock.lang.Specification

import java.security.Security

import static com.brambolt.wildfly.security.credential.store.CredentialStores.createClearPasswordCredential
import static com.brambolt.wildfly.security.credential.store.CredentialStores.retrieveClearPassword

class CredentialStoresSpec extends Specification {

  @Rule TemporaryFolder testProjectDir = new TemporaryFolder()

  def setupSpec() {
    Security.addProvider(new WildFlyElytronProvider())
  }

  def 'create a credential store'() {
    when:
    def file = new File(testProjectDir.root, 'elly.store.tmp')
    def password = 'elly.password'
    def store = CredentialStores.create(file, password, true)
    then:
    null != store
    file.exists()
    cleanup:
    file.delete()
  }

  def 'add and retrieve an alias and a secret'() {
    given:
    def file = new File(testProjectDir.root, 'elly.store.tmp')
    def password = 'elly.password'
    def alias = 'elly.alias'
    def secret = 'elly.secret'
    when:
    !file.exists()
    def store = CredentialStores.create(file, password, true)
    def credential = createClearPasswordCredential(secret)
    store.store(alias, credential)
    then:
    file.exists()
    secret == new String(retrieveClearPassword(store, alias))
    cleanup:
    file.delete()
  }
}
