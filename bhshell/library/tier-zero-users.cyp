// name: tier-zero-users
// description: Enabled users tagged Tier Zero
MATCH (u:User:Tag_Tier_Zero) WHERE u.enabled = true RETURN u
