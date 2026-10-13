// name: asrep-roastable-users
// description: Enabled users without Kerberos pre-authentication
MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u
