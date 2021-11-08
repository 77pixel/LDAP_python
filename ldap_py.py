import ldap

class LDAPcon:

    domena = 'domena'

    def __init__(self):
        self.baza = 'dc=' + self.domena
        self.connect = ldap.initialize('ldap://XXX.XXX.XXX.XXX')
        self.connect.set_option(ldap.OPT_REFERRALS, 0)
        self.connect.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
        self.connect.set_option(ldap.OPT_X_TLS_DEMAND, True)
        self.connect.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        self.connect.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        self.connect.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        self.connect.start_tls_s()

    def login(self, login, passw):
        try:
            self.connect.simple_bind_s(login + '@'+self.domena, passw)
            test = self.connect.search_s(self.baza, ldap.SCOPE_SUBTREE, 'userPrincipalName=' + login + '@'+self.domena)
            tst = test[0]
            ret = self.user_dane(tst)
        except ldap.INVALID_CREDENTIALS: 
            ret = "NOTFOUND"
        return ret

    def dissmis(self):
        self.connect.unbind_s()
        return 1

    def user_dane(self, user):
        
        cnid = user[0]
        test = user[1]
        tel_nr = ''
        nazwa  = ''
        gr     = ''
        mail   = ''
        nrpwz  = ''
        
        try:
            tel_nr = test.get('telephoneNumber')[0]
        except: 
            tel_nr = b"Brak" 
        
        try:
            nazwa =  test.get('displayName')[0]
        except: 
            nazwa = b"Brak" 
        
        try:
            gr = test.get('memberOf')
        except: 
            gr = b"Brak" 

        try:
            mail = test.get('mail')[0]
        except: 
            mail  = b"Brak" 
        
        try:
            imie = test.get('givenName')[0]
        except: 
            imie = b"Brak"

        try:
            nazwisko = test.get('sn')[0]
        except: 
            nazwisko  = b"Brak" 
        
        try:
            nrpwz = test.get('description')[0]
        except: 
            nrpwz  = b"Brak" 
        
        grupy = []
        
        if gr:
            for g in gr:
                sg = str(g, 'UTF-8').split(",")
                grupy.append(sg[0][3:])
                
        return [str(nazwa, 'UTF-8'), str(tel_nr, 'UTF-8'), str(mail, 'UTF-8'), grupy , str(imie, 'UTF-8'), str(nazwisko, 'UTF-8'), str(nrpwz, 'UTF-8'), cnid]
    
    def user_pass(self, user, npass):
        
        tdn="CN=" + user
        tpass = f"\"{npass}\""
    
        try:
            mod_list = [(ldap.MOD_REPLACE, 'unicodePwd', [tpass.encode("UTF-16LE")]),]
            self.connect.modify_s(tdn,mod_list)
            mod_list = [(ldap.MOD_REPLACE, 'pwdLastSet', ["0".encode("UTF-16LE")]),]
            self.connect.modify_s(tdn,mod_list)
            return "OK"

        except Exception as e:
            return str(e)

    def pokaz_liste(self, grupa):
        try:
            test = self.connect.search_s(self.baza, ldap.SCOPE_SUBTREE, "(&(userPrincipalName=*@" + self.domena +")(memberOf=CN="+grupa+"*))")
        except ldap.OPERATIONS_ERROR:
            test = "NOTFOUND"
        return (test)


