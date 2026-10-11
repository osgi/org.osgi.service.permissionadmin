/*******************************************************************************
 * Copyright (c) Contributors to the Eclipse Foundation
 *
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
 *
 * SPDX-License-Identifier: Apache-2.0 
 *******************************************************************************/

package org.osgi.test.cases.permissionadmin.tb1;

import static org.assertj.core.api.Assertions.fail;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

/**
 * A method called by name on an interface the target object implements.
 * The test bundle calls the StartLevel and PackageAdmin services this way so
 * it does not import their packages, which the framework may not provide.
 * (Formerly the MethodCall of the TCK test support library, which only this test
 * bundle used.)
 */
class MethodCall {
	private final String		methodInterface;
	private final String		methodName;
	private final Class< ? >[]	parameters;

	MethodCall(String methodInterface, String methodName,
			Class< ? >... parameters) {
		this.methodInterface = methodInterface;
		this.methodName = methodName;
		this.parameters = parameters;
	}

	String getName() {
		if (methodInterface == null) {
			return methodName;
		}
		return methodInterface + "." + methodName;
	}

	/**
	 * Invokes the method; an InvocationTargetException is unwrapped and its
	 * cause rethrown.
	 */
	Object invoke(Object o, Object... arguments) throws Throwable {
		Class< ? > methodSource = o.getClass();
		if (methodInterface != null) {
			interfaceSearch: while (methodSource != null) {
				for (Class< ? > interf : methodSource.getInterfaces()) {
					if (methodInterface.equals(interf.getName())) {
						methodSource = interf;
						break interfaceSearch;
					}
				}
				methodSource = methodSource.getSuperclass();
			}
			if (methodSource == null) {
				fail("Interface " + methodInterface
						+ " not found on target object.");
			}
		}
		Method m = methodSource.getMethod(methodName, parameters);
		try {
			return m.invoke(o, arguments);
		} catch (InvocationTargetException e) {
			Throwable cause = e.getCause();
			if (cause == null) {
				cause = e;
			}
			throw cause;
		}
	}
}
