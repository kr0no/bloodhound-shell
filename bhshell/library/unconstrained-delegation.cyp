// name: unconstrained-delegation
// description: Enabled computers and users trusted for unconstrained delegation
MATCH (n:Base) WHERE n.unconstraineddelegation = true AND n.enabled = true RETURN n
