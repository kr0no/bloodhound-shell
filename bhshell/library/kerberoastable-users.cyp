// name: kerberoastable-users
// description: Enabled users with an SPN (Kerberoastable)
MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u
