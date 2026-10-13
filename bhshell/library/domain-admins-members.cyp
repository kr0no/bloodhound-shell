// name: domain-admins-members
// description: Direct and nested members of every Domain Admins group
MATCH p=(m:Base)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' RETURN p
