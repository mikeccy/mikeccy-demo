import grails.util.Environment;

import org.codehaus.groovy.grails.commons.ApplicationAttributes
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

import org.springframework.context.ApplicationContext
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService

import utils.SpringSecurityOAuth2ProviderUtility

import test.User
import test.Role
import test.UserRole

class BootStrap {

    def init = { servletContext ->
	
	ApplicationContext applicationContext = servletContext.getAttribute(ApplicationAttributes.APPLICATION_CONTEXT)		

	def conf = SpringSecurityUtils.securityConfig
	if (!conf || !conf.active) {
		return
	}

	SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuth2ProviderSecurityConfig'
	// have to get again after overlaying DefaultOAuthProviderSecurityConfig
	conf = SpringSecurityUtils.securityConfig
	
	if (!conf.oauthProvider.active || !conf.oauthProvider.clients)
		return

	log.debug 'Configuring OAuth2 clients ...'
	
	def clientDetailsService = applicationContext.getBean("clientDetailsService")
	if (clientDetailsService instanceof InMemoryClientDetailsService)
		SpringSecurityOAuth2ProviderUtility.registerClients(conf, clientDetailsService)
	else
		log.info("Client details service bean is not an in-memory implementation, ignoring client config")
	
	log.debug '... done configuring OAuth2 clients'


	// add test user
	if (Environment.current == Environment.DEVELOPMENT) {
		// a test user
		User user = new User(
			username:"admin",
			password:"password",
			enabled:true
		)
		user.save(failOnError:true)
		Role role = new Role(authority:"ROLE_ADMIN")
		role.save(failOnError:true)
		new UserRole(user:user, role:role).save(failOnError:true, flush:true)
	}
    }
    def destroy = {
    }
}
