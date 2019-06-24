package com.mulodo.saml2spspringbootviewer.controller;

import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * @author Cuong Do
 *
 * SAML Controller provides page(s) to send redirect and request to IdPs
 */

@Controller
@RequestMapping("/saml")
public class SAMLController {

	// Logger
	private static final Logger LOGGER = LoggerFactory.getLogger(SAMLController.class);

	@Autowired
	private MetadataManager metadata;

	// discovery page for SSO
	@RequestMapping(value = "/discovery", method = RequestMethod.GET)
	public String idpSelection(HttpServletRequest request, Model model) {
		LOGGER.debug("/discovery");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		boolean isAnonymousToken = authentication instanceof AnonymousAuthenticationToken;
		if (authentication == null) {
			LOGGER.debug("authentication=null");
		} else {
			LOGGER.debug("isAnonymousToken="+isAnonymousToken);
		}
		if (authentication == null || isAnonymousToken) {
			// display list of IdP(s) for user to choose one and do SSO
			Set<String> idps = metadata.getIDPEntityNames();
			LOGGER.debug("List Configured IdP(s) for SSO: " + idps);
			model.addAttribute("idps", idps);
			return "discovery";
		} else {
			// redirect to SP service (dashboard page) if authenticated
			LOGGER.debug("authenticated");
			return "redirect:/dashboard";
		}
	}

}
