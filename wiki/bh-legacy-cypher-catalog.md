# BloodHound Legacy Cypher Catalog (for Max)

This document inventories all Neo4j/Cypher usage in `max.py` to aid migration to BloodHound Community Edition (BHCE).

## Labels, relationships, and properties used

- Node labels
  - User, Group, Computer, Domain
- Relationships (edges)
  - MemberOf, HasSession, AdminTo, AllExtendedRights, AddMember, ForceChangePassword, GenericAll, GenericWrite, Owns, WriteDacl, WriteOwner, ReadLAPSPassword, ReadGMSAPassword, Contains, GpLink, CanRDP, CanPSRemote, ExecuteDCOM, AllowedToDelegate, AddAllowedToAct, AllowedToAct, SQLAdmin, HasSIDHistory, HasSPNConfigured, SharesPasswordWith
- Node properties (selection or output)
  - name, enabled, objectid, unconstraineddelegation, dontreqpreauth, hasspn, description, haslaps, passwordnotreqd, lastlogon, lastlogontimestamp, operatingsystem, highvalue, owned, serviceprincipalnames, cracked, nt_hash, lm_hash, ntds_uname, password, pwdlastset, sidhistory, domain

## Module: get-info
- Users (optionally filtered by `enabled`)
  - MATCH (u:User) {enabled} RETURN u.name
- Computers
  - MATCH (n:Computer) RETURN n.name
- Groups
  - MATCH (n:Group) RETURN n.name
- Group members (recursive)
  - MATCH (g:Group {name:"{gname}"}) MATCH (n)-[r:MemberOf*1..]->(g) RETURN DISTINCT n.name
- Group list for user
  - MATCH (u {name:"{uname}"}) MATCH (u)-[r:MemberOf*1..]->(g:Group) RETURN DISTINCT g.name
- All group memberships
  - MATCH (n),(g:Group) MATCH (n)-[r:MemberOf]->(g) RETURN DISTINCT g.name,n.name
- Domain Admins
  - MATCH (n:User)-[r:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' RETURN DISTINCT n.name
- DA sessions
  - MATCH (u:User)-[r:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' WITH COLLECT(u) AS das MATCH (u2:User)<-[r2:HasSession]-(c:Computer) WHERE u2 IN das RETURN DISTINCT u2.name,c.name ORDER BY u2.name
- Domain Controllers
  - MATCH (n:Computer)-[r:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' RETURN DISTINCT n.name
- Unconstrained delegation objects not DCs
  - MATCH (g:Group) WHERE g.objectid ENDS WITH '-516' MATCH (c:Computer)-[MemberOf]->(g) WITH COLLECT(c) AS dcs MATCH (n {unconstraineddelegation:true}) WHERE NOT n IN dcs RETURN n.name
- AS-REP roastable users
  - MATCH (n:User) WHERE n.dontreqpreauth=TRUE RETURN n.name
- Kerberoastable users
  - MATCH (n:User {hasspn:true}) RETURN n.name
- Kerberoastable users with local admin paths
  - MATCH (n:User {hasspn:true}) MATCH p=shortestPath((n)-[r:AdminTo|MemberOf*1..4]->(c:Computer)) RETURN DISTINCT n.name
- Sessions for a user
  - MATCH (m {name:'{uname}'})<-[r:HasSession]-(n:Computer) RETURN DISTINCT n.name
- Local admin to computers
  - MATCH (m {name:'{uname}'})-[r:AdminTo|MemberOf*1..4]->(n:Computer) RETURN DISTINCT n.name
- Admins of a computer (shortest path)
  - MATCH p=shortestPath((m:Computer {name:'{comp}'})<-[r:AdminTo|MemberOf*1..]-(n)) RETURN DISTINCT n.name
- Owned objects
  - MATCH (n) WHERE n.owned=true RETURN n.name
- Groups of owned objects
  - MATCH (n {owned:true}) MATCH (n)-[r:MemberOf*1..]->(g:Group) RETURN DISTINCT n.name,g.name
- High value targets
  - MATCH (n) WHERE n.highvalue=true RETURN n.name
- Descriptions
  - MATCH (n) WHERE n.description IS NOT NULL RETURN n.name,n.description
- Computer-to-computer admin relationships
  - MATCH (n:Computer),(m:Computer) MATCH (n)-[r:MemberOf|AdminTo*1..]->(m) RETURN DISTINCT n.name,m.name ORDER BY n.name
- No LAPS
  - MATCH (c:Computer {haslaps:false}) RETURN c.name
- PasswordNotRequired
  - MATCH (u:User {passwordnotreqd:true}) {enabled} RETURN u.name
- Password last set older than X days
  - MATCH (u:User) WHERE u.pwdlastset < (datetime().epochseconds - ({days} * 86400)) AND NOT u.pwdlastset IN [-1.0,0.0] RETURN u.name,date(datetime({epochSeconds:toInteger(u.pwdlastset)})) AS changedate ORDER BY changedate DESC
- SID history
  - MATCH (n) WHERE n.sidhistory<>[] UNWIND n.sidhistory AS x OPTIONAL MATCH (d:Domain) WHERE x CONTAINS d.objectid OPTIONAL MATCH (m {objectid:x}) RETURN n.name,x,d.name,m.name ORDER BY n.name
- Unsupported OS
  - MATCH (c:Computer) WHERE toLower(c.operatingsystem) =~ '.*(2000|2003|2008|xp|vista| 7 |me).*' RETURN c.name,c.operatingsystem
- Foreign domain privileges
  - MATCH p=(n1)-[r]->(n2) WHERE NOT n1.domain=n2.domain RETURN DISTINCT n1.name,TYPE(r),n2.name ORDER BY TYPE(r)
- Owned to HVT paths
  - MATCH shortestPath((n {owned:True})-[*1..]->(m {highvalue:True})) RETURN DISTINCT n.name
- Path utilities
  - MATCH p=shortestPath((n1 {name:'{start}'})-[rels*1..]->(n2 {name:'{end}'}})) RETURN p
  - MATCH p=allShortestPaths((n1 {name:'{start}'})-[rels*1..]->(n2 {name:'{end}'}})) RETURN p
  - MATCH p=allShortestPaths((n1 {name:'{start}'})-[rels*1..]->(n2 {highvalue:true})) RETURN p
  - MATCH p=allShortestPaths((n1 {owned:true})-[rels*1..]->(n2 {highvalue:true})) RETURN p
- Owned admins (owned users -> computer AdminTo)
  - match (u:User {owned: True})-[r:AdminTo|MemberOf*1..]->(c:Computer) return c.name, "AdministratedBy", u.name order by c, u
- Stale accounts/computers (by lastlogon/lastlogontimestamp)
  - WITH datetime().epochseconds - ({threshold_days} * 86400) AS threshold MATCH (u:User {enabled:TRUE}) WHERE u.lastlogon < threshold AND u.lastlogontimestamp < threshold RETURN u.name
  - WITH datetime().epochseconds - ({threshold_days} * 86400) AS threshold MATCH (c:Computer {enabled:TRUE}) WHERE c.lastlogon < threshold AND c.lastlogontimestamp < threshold RETURN c.name

## Module: mark-owned
- Clear owned flag
  - MATCH (n) WHERE n.owned=true SET n.owned=false
- Mark object as owned (optional notes/password)
  - MATCH (n) WHERE n.name="{uname}" SET n.owned=true [SET n.notes=...] [SET n.password=...] RETURN n

## Module: mark-hvt
- Clear highvalue
  - MATCH (n) WHERE n.highvalue=true SET n.highvalue=false
- Mark object as highvalue (optional notes)
  - MATCH (n) WHERE n.name="{uname}" SET n.highvalue=true [SET n.notes=...] RETURN n

## Module: query
- Pass-through Cypher queries (row/graph)

## Module: export
- For each edge in the set, get outbound targets
  - MATCH (n1 {name:'{node_name}'}) MATCH (n1)-[r:{EDGE}]->(n2) RETURN DISTINCT n2.name

## Module: del-edge
- Delete edges globally or from a starting node
  - MATCH ({name:"{startingnode}"})-[r:{EDGE}]->() DELETE r RETURN COUNT (DISTINCT("{startingnode}"))
  - MATCH p=()-[r:{EDGE}]->() DELETE r RETURN COUNT(DISTINCT(p))

## Module: add-spns
- Create HasSPNConfigured edges
  - MATCH (n:User {name:"{uname}"}) MATCH (m:Computer {name:"{comp}"}) MERGE (m)-[r:HasSPNConfigured {isacl: false}]->(n) return n,m
- Pull users with SPNs from BH
  - MATCH (n:User {hasspn:true}) RETURN n.name,n.serviceprincipalnames

## Module: add-spw
- Create bidirectional SharesPasswordWith
  - MATCH (n {name:"{name1}"}),(m {name:"{name2}"}) MERGE (n)-[r1:SharesPasswordWith]->(m) MERGE (m)-[r2:SharesPasswordWith]->(n) return n,m

## Module: dpat (Domain Password Audit Tool)
- Map NTDS users to BH and tag properties
  - MATCH (u:User) WHERE u.name='{username1}' OR (u.name STARTS WITH '{username2}@' AND u.objectid ENDS WITH '-{rid}') SET u.cracked={bool} SET u.nt_hash='{nt}' SET u.lm_hash='{lm}' SET u.ntds_uname='{ntds}' [SET u.password='{pwd}'] RETURN u.name,u.objectid
- Clear DPAT tags
  - MATCH (u:User) REMOVE u.cracked REMOVE u.nt_hash REMOVE u.lm_hash REMOVE u.ntds_uname REMOVE u.password
- Count mapped users
  - MATCH (u:User) WHERE u.cracked IS NOT NULL RETURN COUNT(u.name)
- Lookups
  - MATCH (u:User {cracked:true}) WHERE u.password='{pwd}' RETURN u.name
  - MATCH (u:User) WHERE toUpper(u.name)='{uname}' OR toUpper(u.ntds_uname)='{uname}' RETURN u.name,u.password
- DPAT summary queries (selection below; see code for full list)
  - MATCH (u:User) RETURN DISTINCT u.enabled,u.ntds_uname,u.nt_hash,u.password
  - MATCH (u:User {cracked:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash
  - MATCH (u:User {cracked:true,hasspn:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash
  - MATCH (u:User {cracked:true,dontreqpreauth:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u_nt_hash
  - MATCH (u:User {cracked:true,unconstraineddelegation:true}) RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u_nt_hash
  - MATCH (u:User {cracked:true}) WHERE u.lastlogon < (datetime().epochseconds - (182 * 86400)) AND NOT u.lastlogon IN [-1.0, 0.0] RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash
  - MATCH (u:User {cracked:true}) WHERE u.pwdlastset < (datetime().epochseconds - (365 * 86400)) AND NOT u.pwdlastset IN [-1.0, 0.0] RETURN DISTINCT u.enabled,u.ntds_uname,u.password,u.nt_hash
  - Group-based DA/EA/Admin groups, cracked variants (regex on objectid -512, -519, -544)
  - Path-based “intense” queries using shortestPath/allShortestPaths
- Supporting data for stats
  - MATCH (u:User) WHERE u.nt_hash IS NOT NULL RETURN u.nt_hash,u.ntds_uname
  - MATCH (u:User)-[:MemberOf]->(g:Group) RETURN DISTINCT g.name,u.name,u.cracked
  - MATCH (u:User) WHERE u.cracked IS NOT NULL RETURN u.ntds_uname,u.password,u.nt_hash,u.pwdlastset
  - MATCH (u:User) RETURN COUNT(DISTINCT(u.nt_hash))
  - MATCH (u:User {cracked:True}) RETURN COUNT(DISTINCT(u)),COUNT(DISTINCT(u.password))
  - MATCH (u:User) WHERE u.lm_hash IS NOT NULL AND NOT u.lm_hash='aad3b435b51404eeaad3b435b51404ee' RETURN u.lm_hash,count(u.lm_hash)
  - MATCH (u:User) WHERE u.lm_hash IS NOT NULL AND NOT u.lm_hash='aad3b435b51404eeaad3b435b51404ee' RETURN u.name,u.lm_hash
  - MATCH (u:User {cracked:true}) WHERE toUpper(SPLIT(u.name,'@')[0])=toUpper(u.password) RETURN u.ntds_uname,u.password,u.nt_hash
  - MATCH (u:User {cracked:true}) WHERE NOT u.password='' RETURN  COUNT(SIZE(u.password)), SIZE(u.password) AS sz ORDER BY sz DESC
  - MATCH (u:User {cracked:true}) WHERE NOT u.password='' RETURN COUNT(u.password) AS countpwd, u.password ORDER BY countpwd DESC
- Post-processing helper actions
  - MATCH (u:User {cracked:True}) SET u.owned=true
  - MATCH (u:User {cracked=True} SET u.notes="Password Cracked"  [Note: code has a small syntax issue here]

## Notes
- Path-returning queries use data_format="graph" and expect neo4j REST graph response.
- Many selections rely on AD-specific semantics of `objectid` suffixes (-512, -516, -519, -544).
- Some queries intentionally include UNWIND/list processing to extract Users from paths.

This catalog should be used to define BHCE-equivalent data fetches and mutations.
