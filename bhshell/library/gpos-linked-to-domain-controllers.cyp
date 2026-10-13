// name: gpos-linked-to-domain-controllers
// description: GPOs linked to the Domain Controllers OU (control = DC compromise)
MATCH p=(g:GPO)-[:GPLink]->(o:OU) WHERE o.name STARTS WITH 'DOMAIN CONTROLLERS@' RETURN p
