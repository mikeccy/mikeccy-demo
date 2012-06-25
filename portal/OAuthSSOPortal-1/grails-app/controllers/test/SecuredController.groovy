package test

import grails.plugins.springsecurity.Secured

@Secured(["ROLE_ADMIN"])
class SecuredController {

    def index() { }
}
