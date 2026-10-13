// name: owned-to-tier-zero
// description: Shortest paths from owned objects to Tier Zero (raw graph; see also 'path --owned')
MATCH p=allShortestPaths((s:Tag_Owned)-[*1..]->(t:Tag_Tier_Zero)) WHERE s <> t RETURN p LIMIT 1000
