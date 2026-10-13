// name: sid-history
// description: Principals carrying another object's SID (HasSIDHistory)
MATCH p=(n:Base)-[:HasSIDHistory]->(t:Base) RETURN p
