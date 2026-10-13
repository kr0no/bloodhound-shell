// name: domain-trusts
// description: All edges between domains (trusts and trust abuse edges)
MATCH p=(a:Domain)-[r]->(b:Domain) RETURN p
