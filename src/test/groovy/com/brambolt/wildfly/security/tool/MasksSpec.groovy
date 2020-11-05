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

package com.brambolt.wildfly.security.tool

import org.junit.Rule
import org.junit.rules.TemporaryFolder
import spock.lang.Specification

class MasksSpec extends Specification {

  @Rule TemporaryFolder testProjectDir = new TemporaryFolder()

  def 'mask password'() {
    given:
    def password = 'elly.password'
    def salt = '87654321'
    def iterations = 23
    def expected = 'MASK-3IbptpRLrvaVnZLbhWtghV;87654321;23'
    when:
    def masked = Masks.computeMasked(password, salt, iterations)
    then:
    masked == expected
  }

  def 'unmask password'() {
    given:
    def masked = 'MASK-3IbptpRLrvaVnZLbhWtghV;87654321;23'
    def expected = 'elly.password'.toCharArray()
    when:
    def password = Masks.decryptMasked(masked)
    then:
    password == expected
  }
}
