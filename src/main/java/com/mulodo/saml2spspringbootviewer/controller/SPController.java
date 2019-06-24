package com.mulodo.saml2spspringbootviewer.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author Cuong Do
 *
 * Service Provider Controller where provide services (pages, resources, ...) for user
 * The services require authentication via SSO login to access
 */

@Controller
public class SPController {

	// Logger
	private static final Logger LOGGER = LoggerFactory.getLogger(SPController.class);
	
	// index
	@RequestMapping("/")
	public String index() {
		LOGGER.debug("/index");
		return "index";
	}
	
	// dashboard
	@RequestMapping("/dashboard")
	public String landing(Model model) {
		LOGGER.debug("/dashboard");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			LOGGER.debug("authentication=null");
			return "error"; // if security doing right, never go here
		} else {
			LOGGER.debug("authenticated");
		}
		model.addAttribute("userid", getUserIDFromIDP());
		return "dashboard";
	}

	// Get UserID from IDP, should write it in services or whatever, not here
	private String getUserIDFromIDP() {
		SAMLCredential credential = (SAMLCredential) SecurityContextHolder.getContext().getAuthentication().getCredentials();
		String userID = credential.getAttributeAsString("UserID");
		LOGGER.debug(userID);
		return userID;
	}
	
}
