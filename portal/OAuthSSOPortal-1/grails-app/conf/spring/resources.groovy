// Place your Spring DSL code here

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore
import org.springframework.security.oauth2.provider.token.RandomValueTokenServices
import org.springframework.security.oauth2.provider.filter.OAuth2ExceptionHandlerFilter
import org.springframework.security.oauth2.provider.filter.OAuth2ProtectedResourceFilter

beans = {
	def conf = SpringSecurityUtils.securityConfig
	if (!conf || !conf.active) {
		return
	}

	SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuth2ProviderSecurityConfig'
	// have to get again after overlaying DefaultOAuthProviderSecurityConfig
	conf = SpringSecurityUtils.securityConfig
	
	if (!conf.oauthProvider.active)
		return

	log.debug 'Configuring Spring Security OAuth2 provider ...'
	
	clientDetailsService(InMemoryClientDetailsService)
	tokenStore(InMemoryTokenStore)
	tokenServices(RandomValueTokenServices) {
		tokenStore = ref("tokenStore")
		accessTokenValiditySeconds = conf.oauthProvider.tokenServices.accessTokenValiditySeconds
		refreshTokenValiditySeconds = conf.oauthProvider.tokenServices.refreshTokenValiditySeconds
		reuseRefreshToken = conf.oauthProvider.tokenServices.reuseRefreshToken
		supportRefreshToken = conf.oauthProvider.tokenServices.supportRefreshToken
	}
	authorizationCodeServices(InMemoryAuthorizationCodeServices)
	
	// Oauth namespace
	xmlns oauth:"http://www.springframework.org/schema/security/oauth2"
	
	oauth.'authorization-server'(
			'client-details-service-ref':"clientDetailsService",
			'token-services-ref':"tokenServices",
			'authorization-endpoint-url':conf.oauthProvider.authorizationEndpointUrl,
			'token-endpoint-url':conf.oauthProvider.tokenEndpointUrl) {
		
		oauth.'authorization-code'(
			'services-ref':"authorizationCodeServices",
			'disabled':!conf.oauthProvider.grantTypes.authorizationCode,
			'user-approval-page':conf.oauthProvider.userApprovalEndpointUrl,
			'approval-parameter-name':conf.oauthProvider.authorizationCode.approvalParameterName)
		
		oauth.'implicit'(
			'disabled':!conf.oauthProvider.grantTypes.implicit
		)
		oauth.'refresh-token'(
			'disabled':!conf.oauthProvider.grantTypes.refreshToken
		)
		oauth.'client-credentials'(
			'disabled':!conf.oauthProvider.grantTypes.clientCredentials
		)
		oauth.'password'(
			'authentication-manager-ref':'authenticationManager',
			'disabled':!conf.oauthProvider.grantTypes.password
		)
	}
		
	// Register endpoint URL filter since we define the URLs above
	SpringSecurityUtils.registerFilter 'oauth2EndpointUrlFilter',
			conf.oauthProvider.filterStartPosition + 1
			
	oauth2ExceptionHandlerFilter(OAuth2ExceptionHandlerFilter)
	SpringSecurityUtils.registerFilter 'oauth2ExceptionHandlerFilter',
			conf.oauthProvider.filterStartPosition + 2
	oauth2ProtectedResourceFilter(OAuth2ProtectedResourceFilter) {
		tokenServices = ref("tokenServices")
	}
	SpringSecurityUtils.registerFilter 'oauth2ProtectedResourceFilter',
			conf.oauthProvider.filterStartPosition + 3
	
	log.debug "... done configured Spring Security OAuth2 provider"
}
