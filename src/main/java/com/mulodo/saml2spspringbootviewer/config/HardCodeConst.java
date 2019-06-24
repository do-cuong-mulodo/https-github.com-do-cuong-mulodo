package com.mulodo.saml2spspringbootviewer.config;

/**
 * @author Cuong Do
 *
 * Configuration data
 * Temporarily hard code
 * Will be loaded from application.properties or whatever in the future
 */

public class HardCodeConst {
	
	// metadataGenerator
	public static final String APP_ENTITY_ID = "com:vdenotaris:spring:sp";
	public static final String APP_ENTITY_BASE_URL = "https://mulodo.com/entity";
	
	// idpMetadataProvider
	public static final String ONELOGIN_METADATA_URL = "https://mulodo.com/login";
	
	// idpMetadataProvider
	public static final String IDP_SSO_CIRCLE_METADATA_URL = "https://idp.ssocircle.com/idp-meta.xml";
	
	// keyManager
	public static final String SAML_KEYSTORE_FILE_PATH = "saml/samlKeystore.jks";
	public static final String JKS_KEY_MANAGER_STORE_PASS = "nalle123";
	public static final String JKS_KEY_MANAGER_PW_KEY = "apollo";
	public static final String JKS_KEY_MANAGER_PW_VALUE = "nalle123";
	public static final String JKS_KEY_MANAGER_DEFAULT_KEY = "apollo";
	
	// login and logout successfully page redirect
	public static final String REDIRECT_PAGE_AFTER_LOGGED_IN = "/dashboard";
	public static final String REDIRECT_PAGE_AFTER_LOGGED_OUT = "/";
	
}
