// name: dcsync-principals
// description: Principals with DCSync or replication rights on a domain
MATCH p=(n:Base)-[:DCSync|GetChanges|GetChangesAll]->(d:Domain) RETURN p
