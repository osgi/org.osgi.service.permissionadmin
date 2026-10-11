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

import java.io.InputStream;
import java.net.URL;
import java.util.List;
import java.util.PropertyPermission;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.osgi.framework.AdaptPermission;
import org.osgi.framework.AdminPermission;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.framework.startlevel.FrameworkStartLevel;
import org.osgi.service.permissionadmin.PermissionAdmin;
import org.osgi.service.permissionadmin.PermissionInfo;
import org.osgi.test.cases.permissionadmin.service.PermissionSignatureTBCService;
import org.osgi.test.common.annotation.InjectBundleContext;
import org.osgi.test.common.annotation.InjectBundleInstaller;
import org.osgi.test.common.install.BundleInstaller;

/**
 * Contains the test methods of the permission signature test case.
 * 
 * @author Petia Sotirova
 * @version 1.1
 */
public class PermissionSignatureTestControl {

	@InjectBundleContext
	BundleContext		context;

	@InjectBundleInstaller
	BundleInstaller		installer;

	private PermissionSignatureTBCService	tbc;
	private PermissionAdmin					permissionAdmin;

	private Bundle							testBundle;
	private String							testBundleLocation;

	private Bundle							testSignatureBundle;
	private String							signatureBundleLocation;

	private String							signatureBundleName;

	private PermissionSignatureUtility		utility;

	private String							resourceName;
	private String							resourcesName;
	private String							entryName;
	private String							entryPath;
	private String							className;
	private String							extensionEntryName;
	private String							extensionEntryPath;
	private String							extensionClassName;

	private int								startLevel				= 10;
	private int								initialBundleStartLevel	= 10;
	private boolean							checkStartLevelService	= false;
	private boolean							checkPackageAdminService	= false;

	private String							extensionBundleName;
	private static PermissionInfo			adapt					= new PermissionInfo(
																			AdaptPermission.class
																					.getName(),
																			"*",
																			"adapt");
	private static PermissionInfo			property				= new PermissionInfo(
																			PropertyPermission.class
																					.getName(),
																			"org.osgi.test.*",
																			"read");

	@BeforeEach
	public void setUp() throws Exception {
		assertThat(System
				.getSecurityManager()).as("Must have a security manager").isNotNull();
		permissionAdmin = context.getService(serviceReference(PermissionAdmin.class));
		assertThat(permissionAdmin).isNotNull();

		testBundle = installer.installBundle(context.getBundle().getEntry("tb1.jar"), false);
		testBundleLocation = testBundle.getLocation();
		permissionAdmin.setPermissions(testBundleLocation, null);
		testBundle.start();

		signatureBundleName = SignatureResource.getString("bundle.name");
		resourceName = SignatureResource.getString("resource.name");
		resourcesName = SignatureResource.getString("resources.name");
		entryName = SignatureResource.getString("entry.name");
		entryPath = SignatureResource.getString("entry.path");
		className = SignatureResource.getString("load.class");

		extensionEntryName = SignatureResource
				.getString("extension.entry.name");
		extensionEntryPath = SignatureResource
				.getString("extension.entry.path");
		extensionClassName = SignatureResource
				.getString("extension.load.class");

		extensionBundleName = SignatureResource
				.getString("extensionBundle.name");

		tbc = context.getService(serviceReference(PermissionSignatureTBCService.class));
		FrameworkStartLevel fsl = context.getBundle(0).adapt(
				FrameworkStartLevel.class);
		startLevel = fsl.getStartLevel();
		initialBundleStartLevel = fsl.getInitialBundleStartLevel();
		checkStartLevelService = serviceAvailable("org.osgi.service.startlevel.StartLevel");
		checkPackageAdminService = serviceAvailable("org.osgi.service.packageadmin.PackageAdmin");

		utility = new PermissionSignatureUtility(this, tbc);

		testSignatureBundle = installer.installBundle(context.getBundle().getEntry(signatureBundleName), false);
		signatureBundleLocation = testSignatureBundle.getLocation();
		permissionAdmin.setPermissions(signatureBundleLocation, null);
		testSignatureBundle.start();
	}

	@AfterEach
	public void tearDown() throws Exception {
		System.out.println("#after each run");
		testSignatureBundle.uninstall();
		permissionAdmin.setPermissions(signatureBundleLocation, null);
		testBundle.uninstall();
		permissionAdmin.setPermissions(testBundleLocation, null);
	}

	/**
	 * Tests AdminPermission. Checks if a bundle with NoPermission can not
	 * execute anything that requires AdminPermission.
	 */
	@Test
	public void testPermission() throws Throwable {
		permissionAdmin.setPermissions(testBundleLocation,
				new PermissionInfo[0]);
		printPermissions(testBundleLocation);
		String message = "";

		// Each bundle must be given AdminPermission(<bundle id>, "resource") so
		// that it can access it's own resources.
		utility.allowed_Bundle_getResource(message, testBundle, resourceName);
		utility.allowed_Bundle_getResources(message, testBundle, resourcesName);
		utility.allowed_Bundle_getEntry(message, testBundle, resourceName);
		utility.allowed_Bundle_getEntryPaths(message, testBundle, "/META-INF/");

		utility.not_allowed_Bundle_getHeaders(message, testSignatureBundle);
		utility.not_allowed_Bundle_getHeaders_byLocation(message,
				testSignatureBundle);
		utility.not_allowed_Bundle_getLocation(message, testSignatureBundle);
		utility.not_allowed_Bundle_getResource(message, testSignatureBundle,
				resourceName);
		utility.not_allowed_Bundle_getResources(message, testSignatureBundle,
				resourcesName);
		utility.not_allowed_Bundle_getEntry(message, testSignatureBundle,
				entryName);
		utility.not_allowed_Bundle_getEntryPaths(message, testSignatureBundle,
				entryPath);
		utility.not_allowed_BundleStartLevel_setStartLevel(message,
				testSignatureBundle, startLevel);
		utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
				startLevel);
		utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
				message, initialBundleStartLevel);
		if (checkStartLevelService) {
			utility.not_allowed_StartLevel_setBundleStartLevel(message,
					testSignatureBundle, startLevel);
			utility.not_allowed_StartLevel_setStartLevel(message, startLevel);
			utility.not_allowed_StartLevel_setInitialBundleStartLevel(message,
					initialBundleStartLevel);
		}
		utility.not_allowed_Bundle_loadClass(message, testSignatureBundle,
				className);
		utility.not_allowed_Bundle_stop(message, testSignatureBundle);
		utility.not_allowed_Bundle_start(message, testSignatureBundle);
		utility.not_allowed_Bundle_update(message, testSignatureBundle);
		utility.not_allowed_Bundle_update_by_InputStream(message,
				testSignatureBundle, getInputStream(signatureBundleName));
		utility.not_allowed_Bundle_uninstall(message, testSignatureBundle);
		utility.not_allowed_BundleContext_addBundleListener(message,
				testSignatureBundle);
		utility.not_allowed_BundleContext_removeBundleListener(message,
				testSignatureBundle);
		if (checkPackageAdminService) {
			utility.not_allowed_PackageAdmin_refreshPackages(message,
					new Bundle[] {testSignatureBundle});
			utility.not_allowed_PackageAdmin_resolveBundles(message,
					new Bundle[] {testSignatureBundle});
		}
		utility.not_allowed_FrameworkWiring_refreshBundles(message,
				testSignatureBundle);
		utility.not_allowed_FrameworkWiring_resolveBundles(message,
				testSignatureBundle);
		utility.not_allowed_PermissionAdmin_setPermissions(message,
				signatureBundleLocation,
				new PermissionInfo[] {new PermissionInfo(AdminPermission.class
						.getName(), "*", "*")});
		utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
				permissionAdmin.getDefaultPermissions());
	}

	/**
	 * Tests AdminPermission with all actions allowed on all. Checks if a bundle
	 * with AllPermission can execute all methods requiring AdminPermission.
	 */
	@Test
	public void testAdminPermission() throws Throwable {
		PermissionInfo admin = new PermissionInfo(AdminPermission.class
				.getName(), "*", "*");
		permissionAdmin.setPermissions(testBundleLocation,
				new PermissionInfo[] {admin, property});
		printPermissions(testBundleLocation);
		String message = "";

		utility.allowed_Bundle_getHeaders(message, testSignatureBundle);
		utility.allowed_Bundle_getHeaders_byLocation(message,
				testSignatureBundle);
		utility.allowed_Bundle_getLocation(message, testSignatureBundle);
		utility.allowed_Bundle_getResource(message, testSignatureBundle,
				resourceName);
		utility.allowed_Bundle_getResources(message, testSignatureBundle,
				resourcesName);
		utility
				.allowed_Bundle_getEntry(message, testSignatureBundle,
						entryName);
		utility.allowed_Bundle_getEntryPaths(message, testSignatureBundle,
				entryPath);
		utility.not_allowed_BundleStartLevel_setStartLevel(message,
				testSignatureBundle, startLevel);
		utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
				startLevel);
		utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
				message,
				initialBundleStartLevel);
		if (checkStartLevelService) {
			utility.allowed_StartLevel_setStartLevel(message, startLevel);
			utility.allowed_StartLevel_setInitialBundleStartLevel(message,
					initialBundleStartLevel);
		}
		utility.allowed_Bundle_loadClass(message, testSignatureBundle,
				className);
		utility.allowed_Bundle_stop(message, testSignatureBundle);
		utility.allowed_Bundle_start(message, testSignatureBundle);
		utility.allowed_Bundle_update(message, testSignatureBundle);
		utility.allowed_Bundle_update_by_InputStream(message,
				testSignatureBundle, getInputStream(signatureBundleName));

		utility.allowed_BundleContext_addBundleListener(message,
				testSignatureBundle);
		utility.allowed_BundleContext_removeBundleListener(message,
				testSignatureBundle);
		utility.not_allowed_PermissionAdmin_setPermissions(message,
				signatureBundleLocation,
				new PermissionInfo[] {new PermissionInfo(AdminPermission.class
						.getName(), "*", "*")});
		utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
				permissionAdmin.getDefaultPermissions());
		if (checkPackageAdminService) {
			utility.allowed_PackageAdmin_resolveBundles(message,
					new Bundle[] {testSignatureBundle});
			utility.allowed_PackageAdmin_refreshPackages(message,
					new Bundle[] {testSignatureBundle});
		}
		utility.not_allowed_FrameworkWiring_refreshBundles(message,
				testSignatureBundle);
		utility.not_allowed_FrameworkWiring_resolveBundles(message,
				testSignatureBundle);

	}

	/**
	 * Tests AdaptPermission allowed on all.
	 */
	@Test
	public void testAdaptPermission() throws Throwable {
		PermissionInfo admin = new PermissionInfo(
				AdminPermission.class.getName(), "*", "*");
		permissionAdmin.setPermissions(testBundleLocation,
				new PermissionInfo[] {admin, adapt, property});
		printPermissions(testBundleLocation);
		String message = "";

		utility.allowed_Bundle_getHeaders(message, testSignatureBundle);
		utility.allowed_Bundle_getHeaders_byLocation(message,
				testSignatureBundle);
		utility.allowed_Bundle_getLocation(message, testSignatureBundle);
		utility.allowed_Bundle_getResource(message, testSignatureBundle,
				resourceName);
		utility.allowed_Bundle_getResources(message, testSignatureBundle,
				resourcesName);
		utility.allowed_Bundle_getEntry(message, testSignatureBundle, entryName);
		utility.allowed_Bundle_getEntryPaths(message, testSignatureBundle,
				entryPath);
		utility.allowed_BundleStartLevel_setStartLevel(message,
				testSignatureBundle, startLevel);
		utility.allowed_FrameworkStartLevel_setStartLevel(message,
				startLevel);
		utility.allowed_FrameworkStartLevel_setInitialBundleStartLevel(
				message, initialBundleStartLevel);
		if (checkStartLevelService) {
			utility.allowed_StartLevel_setStartLevel(message, startLevel);
			utility.allowed_StartLevel_setInitialBundleStartLevel(message,
					initialBundleStartLevel);
		}
		utility.allowed_Bundle_loadClass(message, testSignatureBundle,
				className);
		utility.allowed_Bundle_stop(message, testSignatureBundle);
		utility.allowed_Bundle_start(message, testSignatureBundle);
		utility.allowed_Bundle_update(message, testSignatureBundle);
		utility.allowed_Bundle_update_by_InputStream(message,
				testSignatureBundle, getInputStream(signatureBundleName));

		utility.allowed_BundleContext_addBundleListener(message,
				testSignatureBundle);
		utility.allowed_BundleContext_removeBundleListener(message,
				testSignatureBundle);
		utility.not_allowed_PermissionAdmin_setPermissions(
				message,
				signatureBundleLocation,
				new PermissionInfo[] {new PermissionInfo(AdminPermission.class
						.getName(), "*", "*")});
		utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
				permissionAdmin.getDefaultPermissions());
		if (checkPackageAdminService) {
			utility.allowed_PackageAdmin_resolveBundles(message,
					new Bundle[] {testSignatureBundle});
			utility.allowed_PackageAdmin_refreshPackages(message,
					new Bundle[] {testSignatureBundle});
		}
		utility.allowed_FrameworkWiring_refreshBundles(message,
				testSignatureBundle);
		utility.allowed_FrameworkWiring_resolveBundles(message,
				testSignatureBundle);

	}

	/**
	 * Tests AdminPermission with an action parameter - metadata. Checks if a
	 * bundle with AdminPrmission - metadata can execute: - Bundle.getHeaders -
	 * Bundle.getLocation and can not execute anything else that requires other
	 * AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionMetadata() throws Throwable {
		String message = "";
		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.METADATA, testSignatureBundle.getBundleId(),
				testSignatureBundle.getLocation(), testSignatureBundle
						.getSymbolicName());

		PermissionInfo info;
		for (int i = 0; i < permissions.size(); ++i) {
			info = permissions.get(i);
			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			utility.allowed_Bundle_getHeaders(message, testSignatureBundle);
			utility.allowed_Bundle_getHeaders_byLocation(message,
					testSignatureBundle);
			utility.allowed_Bundle_getLocation(message, testSignatureBundle);

			utility.not_allowed_Bundle_getResource(message,
					testSignatureBundle, resourceName);
			utility.not_allowed_Bundle_getResources(message,
					testSignatureBundle, resourcesName);
			utility.not_allowed_Bundle_getEntry(message, testSignatureBundle,
					entryName);
			utility.not_allowed_Bundle_getEntryPaths(message,
					testSignatureBundle, entryPath);

			utility.not_allowed_BundleStartLevel_setStartLevel(message,
					testSignatureBundle, startLevel);
			utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
					startLevel);
			utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
					message, initialBundleStartLevel);
			if (checkStartLevelService) {
				utility.not_allowed_StartLevel_setBundleStartLevel(message,
						testSignatureBundle, startLevel);
				utility.not_allowed_StartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_StartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
			}
			utility.not_allowed_Bundle_loadClass(message, testSignatureBundle,
					className);
			utility.not_allowed_Bundle_stop(message, testSignatureBundle);
			utility.not_allowed_Bundle_start(message, testSignatureBundle);
			utility.not_allowed_Bundle_update(message, testSignatureBundle);
			utility.not_allowed_Bundle_update_by_InputStream(message,
					testSignatureBundle, getInputStream(signatureBundleName));
			utility.not_allowed_Bundle_uninstall(message, testSignatureBundle);
			utility.not_allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);
			if (checkPackageAdminService) {
				utility.not_allowed_PackageAdmin_refreshPackages(message,
						new Bundle[] {testSignatureBundle});
				utility.not_allowed_PackageAdmin_resolveBundles(message,
						new Bundle[] {testSignatureBundle});
			}
			utility.not_allowed_FrameworkWiring_refreshBundles(message,
					testSignatureBundle);
			utility.not_allowed_FrameworkWiring_resolveBundles(message,
					testSignatureBundle);
		}
	}

	/**
	 * Tests AdminPermission with an action parameter - resource. Checks if a
	 * bundle with AdminPrmission - resource can execute: - Bundle.getResource -
	 * Bundle.getEntry - Bundle.getEntryPaths and can not execute anything else
	 * that requires other AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionResource() throws Throwable {
		String message = "";
		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.RESOURCE, testSignatureBundle.getBundleId(),
				testSignatureBundle.getLocation(), testSignatureBundle
						.getSymbolicName());

		PermissionInfo info;
		for (int i = permissions.size() - 1; i >= 0; i--) {
			info = permissions.get(i);

			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			utility.allowed_Bundle_getResource(message, testSignatureBundle,
					resourceName);
			utility.allowed_Bundle_getResources(message, testSignatureBundle,
					resourcesName);
			utility.allowed_Bundle_getEntry(message, testSignatureBundle,
					entryName);
			utility.allowed_Bundle_getEntryPaths(message, testSignatureBundle,
					entryPath);


			utility.not_allowed_Bundle_getHeaders(message, testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders_byLocation(message,
					testSignatureBundle);
			utility
					.not_allowed_Bundle_getLocation(message,
							testSignatureBundle);

			utility.not_allowed_BundleStartLevel_setStartLevel(message,
					testSignatureBundle, startLevel);
			utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
					startLevel);
			utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
					message, initialBundleStartLevel);
			if (checkStartLevelService) {
				utility.not_allowed_StartLevel_setBundleStartLevel(message,
						testSignatureBundle, startLevel);
				utility.not_allowed_StartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_StartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
			}
			utility.not_allowed_Bundle_loadClass(message, testSignatureBundle,
					className);
			utility.not_allowed_Bundle_stop(message, testSignatureBundle);
			utility.not_allowed_Bundle_start(message, testSignatureBundle);
			utility.not_allowed_Bundle_update(message, testSignatureBundle);
			utility.not_allowed_Bundle_update_by_InputStream(message,
					testSignatureBundle, getInputStream(signatureBundleName));
			utility.not_allowed_Bundle_uninstall(message, testSignatureBundle);
			utility.not_allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_PermissionAdmin_setPermissions(message,
					signatureBundleLocation,
					new PermissionInfo[] {new PermissionInfo(
							AdminPermission.class.getName(), "*", "*")});
			utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
					permissionAdmin.getDefaultPermissions());

			// note that in R4.2 a change was made to make resource imply
			// resolve
			if (i == 0) {
				if (checkPackageAdminService) {
					utility.allowed_PackageAdmin_resolveBundles(message,
							new Bundle[] {testSignatureBundle});
					utility.allowed_PackageAdmin_refreshPackages(message,
							new Bundle[] {testSignatureBundle});
				}
				utility.allowed_FrameworkWiring_refreshBundles(message,
						testSignatureBundle);
				utility.allowed_FrameworkWiring_resolveBundles(message,
						testSignatureBundle);
			}
			else {
				if (checkPackageAdminService) {
					utility.not_allowed_PackageAdmin_resolveBundles(message,
							new Bundle[] {testSignatureBundle});
					utility.not_allowed_PackageAdmin_refreshPackages(message,
							new Bundle[] {testSignatureBundle});
				}
				utility.not_allowed_FrameworkWiring_refreshBundles(message,
						testSignatureBundle);
				utility.not_allowed_FrameworkWiring_resolveBundles(message,
						testSignatureBundle);
			}
		}
	}

	/**
	 * Tests AdminPermission with an action parameter - Class. Checks if a
	 * bundle with AdminPrmission - Class can execute: - Bundle.loadClass and
	 * can not execute anything else that requires other AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionClass() throws Throwable {
		String message = "";
		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.CLASS, testSignatureBundle.getBundleId(),
				testSignatureBundle.getLocation(), testSignatureBundle
						.getSymbolicName());

		PermissionInfo info;
		for (int i = permissions.size() - 1; i >= 0; i--) {
			info = permissions.get(i);

			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			utility.allowed_Bundle_loadClass(message, testSignatureBundle,
					className);

			utility.not_allowed_Bundle_getHeaders(message, testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders_byLocation(message,
					testSignatureBundle);
			utility
					.not_allowed_Bundle_getLocation(message,
							testSignatureBundle);
			utility.not_allowed_Bundle_getResource(message,
					testSignatureBundle, resourceName);
			utility.not_allowed_Bundle_getResources(message,
					testSignatureBundle, resourcesName);
			utility.not_allowed_Bundle_getEntry(message, testSignatureBundle,
					entryName);
			utility.not_allowed_Bundle_getEntryPaths(message,
					testSignatureBundle, entryPath);
			utility.not_allowed_BundleStartLevel_setStartLevel(message,
					testSignatureBundle, startLevel);
			utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
					startLevel);
			utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
					message, initialBundleStartLevel);
			if (checkStartLevelService) {
				utility.not_allowed_StartLevel_setBundleStartLevel(message,
						testSignatureBundle, startLevel);
				utility.not_allowed_StartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_StartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
			}
			utility.not_allowed_Bundle_stop(message, testSignatureBundle);
			utility.not_allowed_Bundle_start(message, testSignatureBundle);
			utility.not_allowed_Bundle_update(message, testSignatureBundle);
			utility.not_allowed_Bundle_update_by_InputStream(message,
					testSignatureBundle, getInputStream(signatureBundleName));
			utility.not_allowed_Bundle_uninstall(message, testSignatureBundle);
			utility.not_allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_PermissionAdmin_setPermissions(message,
					signatureBundleLocation,
					new PermissionInfo[] {new PermissionInfo(
							AdminPermission.class.getName(), "*", "*")});
			utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
					permissionAdmin.getDefaultPermissions());

			// note that in R4.2 a change was made to make class imply
			// resolve
			if (i == 0) {
				if (checkPackageAdminService) {
					utility.allowed_PackageAdmin_resolveBundles(message,
							new Bundle[] {testSignatureBundle});
					utility.allowed_PackageAdmin_refreshPackages(message,
							new Bundle[] {testSignatureBundle});
				}
				utility.allowed_FrameworkWiring_refreshBundles(message,
						testSignatureBundle);
				utility.allowed_FrameworkWiring_resolveBundles(message,
						testSignatureBundle);
			}
			else {
				if (checkPackageAdminService) {
					utility.not_allowed_PackageAdmin_resolveBundles(message,
							new Bundle[] {testSignatureBundle});
					utility.not_allowed_PackageAdmin_refreshPackages(message,
							new Bundle[] {testSignatureBundle});
				}
				utility.not_allowed_FrameworkWiring_refreshBundles(message,
						testSignatureBundle);
				utility.not_allowed_FrameworkWiring_resolveBundles(message,
						testSignatureBundle);
			}
		}

	}

	/**
	 * Tests AdminPermission with an action parameter - lifecycle. Checks if a
	 * bundle with AdminPrmission - lifecycle can execute: -
	 * BundleContext.installBundle - Bundle.update - Bundle.uninstall and can
	 * not execute anything else that requires other AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionLifecycle() throws Throwable {
		String message = "";
		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.LIFECYCLE, testSignatureBundle.getBundleId(),
				testSignatureBundle.getLocation(), testSignatureBundle
						.getSymbolicName());

		PermissionInfo info;
		for (int i = 0; i < permissions.size(); ++i) {
			info = permissions.get(i);

			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			utility.not_allowed_Bundle_getHeaders(message, testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders_byLocation(message,
					testSignatureBundle);
			utility
					.not_allowed_Bundle_getLocation(message,
							testSignatureBundle);
			utility.not_allowed_Bundle_getResource(message,
					testSignatureBundle, resourceName);
			utility.not_allowed_Bundle_getResources(message,
					testSignatureBundle, resourcesName);
			utility.not_allowed_Bundle_getEntry(message, testSignatureBundle,
					entryName);
			utility.not_allowed_Bundle_getEntryPaths(message,
					testSignatureBundle, entryPath);
			utility.not_allowed_BundleStartLevel_setStartLevel(message,
					testSignatureBundle, startLevel);
			utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
					startLevel);
			utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
					message, initialBundleStartLevel);
			if (checkStartLevelService) {
				utility.not_allowed_StartLevel_setBundleStartLevel(message,
						testSignatureBundle, startLevel);
				utility.not_allowed_StartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_StartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
			}
			utility.not_allowed_Bundle_loadClass(message, testSignatureBundle,
					className);
			utility.not_allowed_Bundle_stop(message, testSignatureBundle);
			utility.not_allowed_Bundle_start(message, testSignatureBundle);
			utility.not_allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);
			if (checkPackageAdminService) {
				utility.not_allowed_PackageAdmin_refreshPackages(message,
						new Bundle[] {testSignatureBundle});
				utility.not_allowed_PackageAdmin_resolveBundles(message,
						new Bundle[] {testSignatureBundle});
			}
			utility.not_allowed_FrameworkWiring_refreshBundles(message,
					testSignatureBundle);
			utility.not_allowed_FrameworkWiring_resolveBundles(message,
					testSignatureBundle);
			utility.not_allowed_PermissionAdmin_setPermissions(message,
					signatureBundleLocation,
					new PermissionInfo[] {new PermissionInfo(
							AdminPermission.class.getName(), "*", "*")});
			utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
					permissionAdmin.getDefaultPermissions());
		}
	}

	/**
	 * Tests AdminPermission with an action parameter - lifecycle. Checks if a
	 * bundle with AdminPrmission - lifecycle can execute: -
	 * BundleContext.installBundle - Bundle.update - Bundle.uninstall and can
	 * not execute anything else that requires other AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionExtensionLifecycle() throws Throwable {
		String message = "";
		String extensionBundleLocation = getInstallBundleLocation(extensionBundleName);

		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.EXTENSIONLIFECYCLE + ','
						+ AdminPermission.LIFECYCLE, -1, // extension bundle is
				// not yet installed
				extensionBundleLocation, // ?
				null);

		PermissionInfo info;
		for (int i = 0; i < permissions.size(); ++i) {
			info = permissions.get(i);

			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			Bundle extensionBundle = (Bundle) utility
					.allowed_BundleContext_installBundle(message,
							testSignatureBundle,
							extensionBundleLocation);
			utility.allowed_Bundle_update(message, extensionBundle);
			utility.allowed_Bundle_update_by_InputStream(message,
					extensionBundle, getInputStream(extensionBundleName));

			utility.not_allowed_Bundle_getHeaders(message, extensionBundle);
			utility.not_allowed_Bundle_getHeaders_byLocation(message,
					extensionBundle);
			utility.not_allowed_Bundle_getLocation(message, extensionBundle);

			utility.not_allowed_Bundle_getResource(message, extensionBundle,
					resourceName);
			utility.not_allowed_Bundle_getResources(message, extensionBundle,
					resourcesName);
			utility.not_allowed_Bundle_getEntry(message, extensionBundle,
					extensionEntryName);
			utility.not_allowed_Bundle_getEntryPaths(message, extensionBundle,
					extensionEntryPath);

			utility.not_allowed_BundleStartLevel_setStartLevel(message,
					extensionBundle, startLevel);
			utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
					startLevel);
			utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
					message, initialBundleStartLevel);
			if (checkStartLevelService) {
				utility.not_allowed_StartLevel_setBundleStartLevel(message,
						extensionBundle, startLevel);
				utility.not_allowed_StartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_StartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
			}

			utility.not_allowed_Bundle_loadClass(message, extensionBundle,
					extensionClassName);

			utility.not_allowed_Bundle_stop(message, extensionBundle);
			utility.not_allowed_Bundle_start(message, extensionBundle);
			utility.not_allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);
			if (checkPackageAdminService) {
				utility.not_allowed_PackageAdmin_refreshPackages(message,
						new Bundle[] {testSignatureBundle});
				utility.not_allowed_PackageAdmin_resolveBundles(message,
						new Bundle[] {testSignatureBundle});
			}
			utility.not_allowed_FrameworkWiring_refreshBundles(message,
					testSignatureBundle);
			utility.not_allowed_FrameworkWiring_resolveBundles(message,
					testSignatureBundle);
			utility.not_allowed_PermissionAdmin_setPermissions(message,
					extensionBundleLocation,
					new PermissionInfo[] {new PermissionInfo(
							AdminPermission.class.getName(), "*", "*")});
			utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
					permissionAdmin.getDefaultPermissions());

			utility.allowed_Bundle_uninstall(message, extensionBundle);
		}
	}

	/**
	 * Tests AdminPermission with an action parameter - execute. Checks if a
	 * bundle with AdminPrmission - execute can execute: - Bundle.start -
	 * Bundle.stop - StartLevel.setBundleStartLevel and can not execute anything
	 * else that requires other AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionExecute() throws Throwable {
		String message = "";
		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.EXECUTE, testSignatureBundle.getBundleId(),
				testSignatureBundle.getLocation(), testSignatureBundle
						.getSymbolicName());

		PermissionInfo info;
		for (int i = permissions.size() - 1; i >= 0; i--) {
			info = permissions.get(i);

			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			utility.allowed_Bundle_stop(message, testSignatureBundle);
			utility.allowed_Bundle_start(message, testSignatureBundle);

			utility.not_allowed_Bundle_getHeaders(message, testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders_byLocation(message,
					testSignatureBundle);
			utility
					.not_allowed_Bundle_getLocation(message,
							testSignatureBundle);
			utility.not_allowed_Bundle_getResource(message,
					testSignatureBundle, resourceName);
			utility.not_allowed_Bundle_getResources(message,
					testSignatureBundle, resourcesName);
			utility.not_allowed_Bundle_getEntry(message, testSignatureBundle,
					entryName);
			utility.not_allowed_Bundle_getEntryPaths(message,
					testSignatureBundle, entryPath);
			utility.allowed_BundleStartLevel_setStartLevel(message,
					testSignatureBundle, startLevel);
			utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
					startLevel);
			utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
					message, initialBundleStartLevel);
			if (checkStartLevelService) {
				utility.allowed_StartLevel_setBundleStartLevel(message,
						testSignatureBundle, startLevel);
				utility.not_allowed_StartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_StartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
			}
			utility.not_allowed_Bundle_loadClass(message, testSignatureBundle,
					className);
			utility.not_allowed_Bundle_update(message, testSignatureBundle);
			utility.not_allowed_Bundle_update_by_InputStream(message,
					testSignatureBundle, getInputStream(signatureBundleName));
			utility.not_allowed_Bundle_uninstall(message, testSignatureBundle);
			utility.not_allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_PermissionAdmin_setPermissions(message,
					signatureBundleLocation,
					new PermissionInfo[] {new PermissionInfo(
							AdminPermission.class.getName(), "*", "*")});
			utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
					permissionAdmin.getDefaultPermissions());

			// note that in R4.2 a change was made to make execute imply
			// resolve
			if (i == 0) {
				if (checkPackageAdminService) {
					utility.allowed_PackageAdmin_resolveBundles(message,
							new Bundle[] {testSignatureBundle});
					utility.allowed_PackageAdmin_refreshPackages(message,
							new Bundle[] {testSignatureBundle});
				}
				utility.allowed_FrameworkWiring_refreshBundles(message,
						testSignatureBundle);
				utility.allowed_FrameworkWiring_resolveBundles(message,
						testSignatureBundle);
			}
			else {
				if (checkPackageAdminService) {
					utility.not_allowed_PackageAdmin_resolveBundles(message,
							new Bundle[] {testSignatureBundle});
					utility.not_allowed_PackageAdmin_refreshPackages(message,
							new Bundle[] {testSignatureBundle});
				}
				utility.not_allowed_FrameworkWiring_refreshBundles(message,
						testSignatureBundle);
				utility.not_allowed_FrameworkWiring_resolveBundles(message,
						testSignatureBundle);
			}
		}
	}

	/**
	 * Tests AdminPermission with an action parameter - listener. Checks if a
	 * bundle with AdminPrmission - listener can execute: -
	 * BundleContext.addBundleListener - BundleContext.removeBundleListener and
	 * can not execute anything else that requires other AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionListener() throws Throwable {
		String message = "";
		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.LISTENER, testSignatureBundle.getBundleId(),
				testSignatureBundle.getLocation(), testSignatureBundle
						.getSymbolicName());

		PermissionInfo info;
		for (int i = 0; i < permissions.size(); ++i) {
			info = permissions.get(i);

			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			utility.allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);

			utility.not_allowed_Bundle_getHeaders(message, testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders_byLocation(message,
					testSignatureBundle);
			utility
					.not_allowed_Bundle_getLocation(message,
							testSignatureBundle);
			utility.not_allowed_Bundle_getResource(message,
					testSignatureBundle, resourceName);
			utility.not_allowed_Bundle_getResources(message,
					testSignatureBundle, resourcesName);
			utility.not_allowed_Bundle_getEntry(message, testSignatureBundle,
					entryName);
			utility.not_allowed_Bundle_getEntryPaths(message,
					testSignatureBundle, entryPath);
			utility.not_allowed_BundleStartLevel_setStartLevel(message,
					testSignatureBundle, startLevel);
			utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
					startLevel);
			utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
					message, initialBundleStartLevel);
			if (checkStartLevelService) {
				utility.not_allowed_StartLevel_setBundleStartLevel(message,
						testSignatureBundle, startLevel);
				utility.not_allowed_StartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_StartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
			}
			utility.not_allowed_Bundle_loadClass(message, testSignatureBundle,
					className);
			utility.not_allowed_Bundle_stop(message, testSignatureBundle);
			utility.not_allowed_Bundle_start(message, testSignatureBundle);
			utility.not_allowed_Bundle_update(message, testSignatureBundle);
			utility.not_allowed_Bundle_update_by_InputStream(message,
					testSignatureBundle, getInputStream(signatureBundleName));
			utility.not_allowed_Bundle_uninstall(message, testSignatureBundle);
			if (checkPackageAdminService) {
				utility.not_allowed_PackageAdmin_refreshPackages(message,
						new Bundle[] {testSignatureBundle});
				utility.not_allowed_PackageAdmin_resolveBundles(message,
						new Bundle[] {testSignatureBundle});
			}
			utility.not_allowed_FrameworkWiring_refreshBundles(message,
					testSignatureBundle);
			utility.not_allowed_FrameworkWiring_resolveBundles(message,
					testSignatureBundle);
			utility.not_allowed_PermissionAdmin_setPermissions(message,
					signatureBundleLocation,
					new PermissionInfo[] {new PermissionInfo(
							AdminPermission.class.getName(), "*", "*")});
			utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
					permissionAdmin.getDefaultPermissions());

		}

	}

	/**
	 * Tests AdminPermission with an action parameter - resolve. Checks if a
	 * bundle with AdminPrmission - resolve can execute: -
	 * PackageAdmin.refreshPackages - PackageAdmin.resolveBundles and can not
	 * execute anything else that requires other AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionResolve() throws Throwable {
		String message = "";
		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.RESOLVE, testSignatureBundle.getBundleId(),
				testSignatureBundle.getLocation(),
				testSignatureBundle.getSymbolicName());

		PermissionInfo info;
		for (int i = permissions.size() - 1; i >= 0; i--) {
			info = permissions.get(i);

			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			utility.not_allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders(message, testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders_byLocation(message,
					testSignatureBundle);
			utility
					.not_allowed_Bundle_getLocation(message,
							testSignatureBundle);
			utility.not_allowed_Bundle_getResource(message,
					testSignatureBundle, resourceName);
			utility.not_allowed_Bundle_getResources(message,
					testSignatureBundle, resourcesName);
			utility.not_allowed_Bundle_getEntry(message, testSignatureBundle,
					entryName);
			utility.not_allowed_Bundle_getEntryPaths(message,
					testSignatureBundle, entryPath);
			utility.not_allowed_BundleStartLevel_setStartLevel(message,
					testSignatureBundle, startLevel);
			utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
					startLevel);
			utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
					message, initialBundleStartLevel);
			if (checkStartLevelService) {
				utility.not_allowed_StartLevel_setBundleStartLevel(message,
						testSignatureBundle, startLevel);
				utility.not_allowed_StartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_StartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
			}
			utility.not_allowed_Bundle_loadClass(message, testSignatureBundle,
					className);
			utility.not_allowed_Bundle_stop(message, testSignatureBundle);
			utility.not_allowed_Bundle_start(message, testSignatureBundle);
			utility.not_allowed_Bundle_update(message, testSignatureBundle);
			utility.not_allowed_Bundle_update_by_InputStream(message,
					testSignatureBundle, getInputStream(signatureBundleName));
			utility.not_allowed_Bundle_uninstall(message, testSignatureBundle);
			utility.not_allowed_PermissionAdmin_setPermissions(message,
					signatureBundleLocation,
					new PermissionInfo[] {new PermissionInfo(
							AdminPermission.class.getName(), "*", "*")});
			utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
					permissionAdmin.getDefaultPermissions());

			if (i == 0) {
				if (checkPackageAdminService) {
					utility.allowed_PackageAdmin_resolveBundles(message,
							new Bundle[] {testSignatureBundle});
					utility.allowed_PackageAdmin_refreshPackages(message,
							new Bundle[] {testSignatureBundle});
				}
				utility.allowed_FrameworkWiring_refreshBundles(message,
						testSignatureBundle);
				utility.allowed_FrameworkWiring_resolveBundles(message,
						testSignatureBundle);
			}
			else {
				if (checkPackageAdminService) {
					utility.not_allowed_PackageAdmin_resolveBundles(message,
							new Bundle[] {testSignatureBundle});
					utility.not_allowed_PackageAdmin_refreshPackages(message,
							new Bundle[] {testSignatureBundle});
				}
				utility.not_allowed_FrameworkWiring_refreshBundles(message,
						testSignatureBundle);
				utility.not_allowed_FrameworkWiring_resolveBundles(message,
						testSignatureBundle);
			}

		}

	}

	/**
	 * Tests AdminPermission with an action parameter - startlevel. Checks if a
	 * bundle with AdminPrmission - startlevel can execute: -
	 * StartLevel.setStartLevel - StartLevel.setInitialBundleStartLevel and can
	 * not execute anything else that requires other AdminPermission.
	 * 
	 * The bundle is specified either by bundle id or by filter string.
	 */
	@Test
	public void testAdminPermissionStartlevel() throws Throwable {
		if (!checkStartLevelService) {
			return; // this method shall not be excecuted - no StartLevel
			// service detected
		}
		String message = "";
		List<PermissionInfo> permissions = utility.getPInfosForAdminPermisssion(
				AdminPermission.STARTLEVEL, 0, testSignatureBundle
						.getLocation(), testSignatureBundle.getSymbolicName());

		PermissionInfo info;
		for (int i = 0; i < permissions.size(); ++i) {
			info = permissions.get(i);

			permissionAdmin.setPermissions(testBundleLocation,
					new PermissionInfo[] {info, adapt, property});
			printPermissions(testBundleLocation);

			utility.not_allowed_BundleStartLevel_setStartLevel(message,
					testSignatureBundle, startLevel);
			if (checkStartLevelService) {
				utility.not_allowed_StartLevel_setBundleStartLevel(message,
						testSignatureBundle, startLevel);
			}
			if (i < 2) {
				utility.allowed_FrameworkStartLevel_setStartLevel(message,
						startLevel);
				utility.allowed_FrameworkStartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
				if (checkStartLevelService) {
					utility.allowed_StartLevel_setStartLevel(message,
							startLevel);
					utility.allowed_StartLevel_setInitialBundleStartLevel(
							message, initialBundleStartLevel);
				}
			}
			else {
				utility.not_allowed_FrameworkStartLevel_setStartLevel(message,
						startLevel);
				utility.not_allowed_FrameworkStartLevel_setInitialBundleStartLevel(
						message, initialBundleStartLevel);
				if (checkStartLevelService) {
					utility.not_allowed_StartLevel_setStartLevel(message,
							startLevel);
					utility.not_allowed_StartLevel_setInitialBundleStartLevel(
							message, initialBundleStartLevel);
				}
			}

			utility.not_allowed_BundleContext_addBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_BundleContext_removeBundleListener(message,
					testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders(message, testSignatureBundle);
			utility.not_allowed_Bundle_getHeaders_byLocation(message,
					testSignatureBundle);
			utility
					.not_allowed_Bundle_getLocation(message,
							testSignatureBundle);
			utility.not_allowed_Bundle_getResource(message,
					testSignatureBundle, resourceName);
			utility.not_allowed_Bundle_getResources(message,
					testSignatureBundle, resourcesName);
			utility.not_allowed_Bundle_getEntry(message, testSignatureBundle,
					entryName);
			utility.not_allowed_Bundle_getEntryPaths(message,
					testSignatureBundle, entryPath);
			utility.not_allowed_Bundle_loadClass(message, testSignatureBundle,
					className);
			utility.not_allowed_Bundle_stop(message, testSignatureBundle);
			utility.not_allowed_Bundle_start(message, testSignatureBundle);
			utility.not_allowed_Bundle_update(message, testSignatureBundle);
			utility.not_allowed_Bundle_update_by_InputStream(message,
					testSignatureBundle, getInputStream(signatureBundleName));
			utility.not_allowed_Bundle_uninstall(message, testSignatureBundle);
			if (checkPackageAdminService) {
				utility.not_allowed_PackageAdmin_refreshPackages(message,
						new Bundle[] {testSignatureBundle});
				utility.not_allowed_PackageAdmin_resolveBundles(message,
						new Bundle[] {testSignatureBundle});
			}
			utility.not_allowed_FrameworkWiring_refreshBundles(message,
					testSignatureBundle);
			utility.not_allowed_FrameworkWiring_resolveBundles(message,
					testSignatureBundle);
			utility.not_allowed_PermissionAdmin_setPermissions(message,
					signatureBundleLocation,
					new PermissionInfo[] {new PermissionInfo(
							AdminPermission.class.getName(), "*", "*")});
			utility.not_allowed_PermissionAdmin_setDefaultPermissions(message,
					permissionAdmin.getDefaultPermissions());

		}
	}

	// returns true if 'method' failed
	/** A call on the test bundle's service, made under its current permissions. */
	@FunctionalInterface
	interface TbcCall {
		Object call(PermissionSignatureTBCService tbc) throws Throwable;
	}

	boolean not_allowed_call(String message, TbcCall call,
			Class< ? extends Throwable> wanted)
			throws Exception {
		try {
			call.call(tbc);
		}
		catch (Throwable e) {
			assertThat(e).as(message).isInstanceOf(wanted);
			return true;
		}
		fail(message + " expected:[" + wanted.getName() + "] and got nothing");
		return false;
	}

	boolean not_allowed_call_assertNull(String message, TbcCall call) throws Throwable {
		Object result = call.call(tbc);
		if (result == null) {
			System.out.println(message + " and correctly returns null");
			return true;
		}
		else {
			fail(message + " but returns not null");
			return false;
		}
	}

	boolean allowed_call_assertNotNull(String message, TbcCall call) throws Throwable {
		Object result = call.call(tbc);
		if (result == null) {
			fail(message + " but returns null");
			return false;
		}
		else {
			System.out.println(message + " and correctly returns not null");
			return true;
		}
	}

	Object allowed_call(String message, TbcCall call) {
		try {
			Object result = call.call(tbc);
			System.out.println(message);
			return result;
		}
		catch (Throwable e) {
			fail(message + " but " + e.getClass().getName() + " was thrown", e);
			return null;
		}
	}

	private InputStream getInputStream(String bundleName) throws Exception {
		return (new URL(getInstallBundleLocation(bundleName))).openStream();
	}

	private void printPermissions(String bundleLocation) {
		PermissionInfo[] pi = permissionAdmin.getPermissions(bundleLocation);
		if ((pi == null) || (pi.length == 0)) {
			System.out.println("No permissions for " + bundleLocation);
			return;
		}
		System.out.println("Permissions for " + bundleLocation);
		for (int j = 0; j < pi.length; ++j) {
			System.out.println(pi[j].toString());
		}
	}

	private String getInstallBundleLocation(String bundleName) {
		return context.getBundle().getEntry("/").toExternalForm() + bundleName;
	}

	private boolean serviceAvailable(String clazz) {
		return context.getServiceReference(clazz) != null;
	}

	private <S> ServiceReference<S> serviceReference(Class<S> clazz) {
		ServiceReference<S> ref = context.getServiceReference(clazz);
		assertThat(ref)
				.as("Can't get service reference for " + clazz.getName())
				.isNotNull();
		return ref;
	}
}
