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
package org.osgi.test.cases.permissionadmin.junit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.FilePermission;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collection;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleException;
import org.osgi.framework.ServiceReference;
import org.osgi.service.permissionadmin.PermissionAdmin;
import org.osgi.service.permissionadmin.PermissionInfo;
import org.osgi.test.cases.permissionadmin.service.ContextSharer;
import org.osgi.test.common.annotation.InjectBundleContext;
import org.osgi.test.common.annotation.InjectBundleInstaller;
import org.osgi.test.common.install.BundleInstaller;

public class MainTests {

	@InjectBundleContext
	BundleContext		context;

	@InjectBundleInstaller
	BundleInstaller		installer;

	@BeforeEach
	public void setUp() throws Exception {
		assertThat(System
				.getSecurityManager()).as("Must have a security manager").isNotNull();
	}

	@AfterEach
	public void tearDown() {
	}

	/** *** Test methods **** */
	@Test
	public void testBasicPermissionInfo() throws Exception {
		/* Construct a permissioninfo from a permission class */
		PermissionInfo permInfo = new PermissionInfo(FilePermission.class
				.getName(), "<<ALL FILES>>", "read");
		assertThat(permInfo.getActions()).as("Actions").isEqualTo("read");
		assertThat(permInfo.getName()).as("Name").isEqualTo("<<ALL FILES>>");
		assertThat(permInfo.getType()).as("Type").isEqualTo("java.io.FilePermission");
		/* Check the output of getEncoded() */
		assertThat(permInfo
						.getEncoded()).as("getEncoded").isEqualTo("(java.io.FilePermission \"<<ALL FILES>>\" \"read\")");
		/* toString() should be identical with getEncoded() */
		assertThat(permInfo.toString()).as("toString").isEqualTo(permInfo.getEncoded());
	}

	@Test
	public void testEqual() throws Exception {
		/* Construct an identical permissionInfo and check equal */
		PermissionInfo permInfo = new PermissionInfo(FilePermission.class
				.getName(), "<<ALL FILES>>", "read");
		PermissionInfo identicalPermInfo = new PermissionInfo(
				FilePermission.class.getName(), "<<ALL FILES>>", "read");
		assertThat(identicalPermInfo).as("identical").isEqualTo(permInfo);
		assertThat(identicalPermInfo.hashCode()).as("identical hashcodes").isEqualTo(permInfo.hashCode());
		/* Construct another permissionInfo, not identical and check equal */
		PermissionInfo unIdenticalPermInfo = new PermissionInfo(
				FilePermission.class.getName(), "<<ALL FILES>>", "write");
		/*
		 * QUESTION: Is this test relevant? Should there be an assert for
		 * notEqual?
		 */
		assertThat(!permInfo.equals(unIdenticalPermInfo)).as("not identical").isTrue();
	}

	@Test
	public void testEncodedPermission() throws Exception {
		/*
		 * Check if permissioninfos created from encoded are identical to the
		 * original
		 */
		PermissionInfo permInfo = new PermissionInfo(FilePermission.class
				.getName(), "<<ALL FILES>>", "read");
		String stringEncodedPermInfo = permInfo.getEncoded();
		PermissionInfo stringPermInfo = new PermissionInfo(
				stringEncodedPermInfo);
		/* Construct a normal permission info */
		PermissionInfo identicalPermInfo = new PermissionInfo(
				FilePermission.class.getName(), "<<ALL FILES>>", "read");
		assertThat(identicalPermInfo).as("constructed from a string").isEqualTo(stringPermInfo);
		assertThat(permInfo.toString()).as("toString").isEqualTo(stringEncodedPermInfo);
	}

	/**
	 * Tests various illegal ways to construct PermissionInfo objects with an
	 * encoded string. WARNING! Many of these tests checks things that are not
	 * well defined in the current spec!
	 */
	@Test
	public void testExceptionalPermissionInfo() throws Exception {
		/* !!! This is not explicitly specified in the spec */
		createBadPermissionInfo("null argument", null,
				NullPointerException.class);
		createBadPermissionInfo("Empty argument", "",
				IllegalArgumentException.class);
		createBadPermissionInfo("Only parenthesis", "()",
				IllegalArgumentException.class);
		createBadPermissionInfo("Missing open parenthesis",
				"java.io.FilePermission \"<<ALL FILES>>\" \"read\")",
				IllegalArgumentException.class);
		createBadPermissionInfo("Missing closing parentheses",
				"(java.io.FilePermission \"<<ALL FILES>>\" \"read\"",
				IllegalArgumentException.class);
		createBadPermissionInfo("Quotes on type",
				"\"java.io.FilePermission\" \"<<ALL FILES>>\" \"read\")",
				IllegalArgumentException.class);
		createBadPermissionInfo("Open quote on type",
				"\"java.io.FilePermission \"<<ALL FILES>>\" \"read\")",
				IllegalArgumentException.class);
		createBadPermissionInfo("Closing quote on type",
				"java.io.FilePermission\" \"<<ALL FILES>>\" \"read\")",
				IllegalArgumentException.class);
		createBadPermissionInfo("Missing open name quote",
				"(java.io.FilePermission <<ALL FILES>>\" \"read\")",
				IllegalArgumentException.class);
		createBadPermissionInfo("Missing close name quote",
				"(java.io.FilePermission \"<<ALL FILES>> \"read\")",
				IllegalArgumentException.class);
		createBadPermissionInfo("Missing open action quote",
				"(java.io.FilePermission \"<<ALL FILES>>\" read\")",
				IllegalArgumentException.class);
		createBadPermissionInfo("Missing close action quote",
				"(java.io.FilePermission \"<<ALL FILES>>\" \"read)",
				IllegalArgumentException.class);
		createBadPermissionInfo(
				"Too many arguments",
				"(java.io.FilePermission \"<<ALL FILES>>\" \"read\" \"write\")",
				IllegalArgumentException.class);
		createBadPermissionInfo("Comma separation between name and action",
				"(java.io.FilePermission \"<<ALL FILES>>\", \"read\")",
				IllegalArgumentException.class);
	}

	/**
	 * Tests various variations of the arguments when constructing
	 * PermissionInfo objects. WARNING! Many of these tests checks things that
	 * are not well defined in the current spec!
	 */
	@Test
	public void testPermissionInfo() throws Exception {
		PermissionInfo info = null;
		/* Test constructor with null type */
		createBadPermissionInfo("null arguments", null, null, null,
				NullPointerException.class);
		createBadPermissionInfo("null arguments", null, "<<ALL FILES>>", null,
				NullPointerException.class);
		createBadPermissionInfo("null arguments", null, "<<ALL FILES>>",
				"read", NullPointerException.class);
		createBadPermissionInfo("null arguments", null, null, "read",
				NullPointerException.class);
		/* Test constructor with null name and actions arguments */
		info = new PermissionInfo("java.io.FilePermission", null, null);
		assertThat(info.getType()).as("type").isEqualTo("java.io.FilePermission");
		assertThat(info.getName()).as("no name").isNull();
		assertThat(info.getActions()).as("no actions").isNull();
		assertThat(info.getEncoded()).as("encoded").isEqualTo("(java.io.FilePermission)");
		assertThat(info.toString()).as("toString").isEqualTo("(java.io.FilePermission)");
		System.out.println("hashcode " + info.hashCode());
		/* Test constructor with null actions argument */
		info = new PermissionInfo("java.io.FilePermission", "<<ALL FILES>>",
				null);
		assertThat(info.getType()).as("type").isEqualTo("java.io.FilePermission");
		assertThat(info.getName()).as("name").isEqualTo("<<ALL FILES>>");
		assertThat(info.getActions()).as("no actions").isNull();
		assertThat(info.getEncoded()).as("encoded").isEqualTo("(java.io.FilePermission \"<<ALL FILES>>\")");
		assertThat(info.toString()).as("toString").isEqualTo("(java.io.FilePermission \"<<ALL FILES>>\")");
		System.out.println("hashcode " + info.hashCode());
		/* Test constructor with missing name argument */
		createBadPermissionInfo("missing name", "java.io.FilePermission", null,
				"read", IllegalArgumentException.class);
		/* Test constructor with no null arguments */
		info = new PermissionInfo("java.io.FilePermission", "<<ALL FILES>>",
				"read");
		assertThat(info.getType()).as("type").isEqualTo("java.io.FilePermission");
		assertThat(info.getName()).as("name").isEqualTo("<<ALL FILES>>");
		assertThat(info.getActions()).as("actions").isEqualTo("read");
		assertThat(info
						.getEncoded()).as("encoded").isEqualTo("(java.io.FilePermission \"<<ALL FILES>>\" \"read\")");
		assertThat(info
						.toString()).as("toString").isEqualTo("(java.io.FilePermission \"<<ALL FILES>>\" \"read\")");
		System.out.println("hashcode " + info.hashCode());
	}

	/**
	 * Makes sure that Bundle 0 (system bundle) is the one that registered the
	 * PermissionAdmin service.
	 */
	@Test
	public void testBundleZero() throws Exception {
		ServiceReference<PermissionAdmin> serviceRef = context
				.getServiceReference(PermissionAdmin.class);
		Bundle bundle = serviceRef.getBundle();
		assertThat(bundle
				.getBundleId()).as("Bundle that registered PermissionAdmin").isZero();
	}

	/**
	 * thereCanBeonlyOne. Test that there is only one permission admin
	 */
	@Test
	public void testThereCanBeOnlyOne() throws Exception {
		/* Get the references to all permissions admins */
		Collection<ServiceReference<PermissionAdmin>> serviceRefs = context
				.getServiceReferences(PermissionAdmin.class, null);
		assertThat(serviceRefs).as("only one PermissionAdmin").hasSize(1);
	}

	/**	
	 */
	@Test
	public void testImplicitPermissions() throws Throwable {
		PermissionInfo[] invokePerm = {new PermissionInfo(
				"java.security.AllPermission", "", "")};
		invokeWithPermissions("implicitPermissionsTest", invokePerm, false);
		invokePerm = new PermissionInfo[0];
		invokeWithPermissions("implicitPermissionsTest", invokePerm, true);
	}

	@Test
	public void testNoPermissions() throws Throwable {
		Bundle tb4 = installer.installBundle(context.getBundle().getEntry("tb4.jar"), false);
		try {
			tb4.start();
		}
		catch (BundleException e) {
			fail("Unexpected Exception", e.getCause());
		}
		finally {
			tb4.uninstall();
		}
	}

	/* called by testImplicitPermissions */
	public void implicitPermissionsTest() throws Exception {
		context.getBundle().getBundleContext().getDataFile("nicke.txt");
	}

	private void invokeWithPermissions(String methodName,
			PermissionInfo[] perms, boolean fail) throws Throwable {
		/* Install and start the context sharing bundle */
		Bundle contextBundle = installer.installBundle(context.getBundle().getEntry("contextsharer.jar"), true);
		try {
			String contextBundleLocation = contextBundle.getLocation();

			/* Get the context sharing service */
			ServiceReference<ContextSharer> sr = context
					.getServiceReference(ContextSharer.class);
			ContextSharer cs = context.getService(sr);

			/* Get the PermissionAdmin service */
			ServiceReference<PermissionAdmin> paRef = context
					.getServiceReference(PermissionAdmin.class);
			PermissionAdmin pa = context.getService(
					paRef);

			/* Set the permissions for the context sharing bundle */
			pa.setPermissions(contextBundleLocation, perms);

			/*
			 * Make the context sharer invoke the specified method on this
			 * object and thereby calling the method with its permissions
			 */
			Method m = this.getClass().getDeclaredMethod(methodName,
					new Class[0]);
			try {
				cs.invoke(this, m);
				if (fail) {
					fail("Expecting a security exception");
				}
			}
			catch (InvocationTargetException e) {
				if (e.getTargetException() instanceof SecurityException) {
					if (!fail) {
						fail("Unexpected security exception", e
								.getTargetException());
					}
				}
				else {
					throw e.getTargetException();
				}
			}
			/* Delete the permissions for the context sharing bundle */
			pa.setPermissions(contextBundleLocation, null);

		}
		finally {
			/* Uninstall the context sharing bundle */
			contextBundle.uninstall();
		}
	}

	/** *** Helper methods **** */
	/**
	 * Creates a PermissionInfo with a bad encoded string and checks that it
	 * throws a correct exception.
	 */
	private void createBadPermissionInfo(String message, String encoded,
			Class< ? extends Throwable> exceptionClass) throws Exception {
		try {
			new PermissionInfo(encoded);
			fail(message + " did not result in a " + exceptionClass.getName());
		}
		catch (Exception e) {
			assertThat(e).as(message).isInstanceOf(exceptionClass);
		}
	}

	/**
	 * Creates a PermissionInfo with a bad encoded string and checks that it
	 * throws a correct exception.
	 */
	private void createBadPermissionInfo(String message, String type,
			String name, String actions,
			Class< ? extends Throwable> exceptionClass) throws Exception {
		try {
			new PermissionInfo(type, name, actions);
			fail(message + " did not result in a " + exceptionClass.getName());
		}
		catch (Exception e) {
			assertThat(e).as(message).isInstanceOf(exceptionClass);
		}
	}

}
