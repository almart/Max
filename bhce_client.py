import requests
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional

class BHCEClient:
    """
    BloodHound Community Edition (BHCE) REST client with login/self/cypher support.
    """

    def __init__(self, base_url: str, timeout: int = 20, verify: bool = True) -> None:
        self.base_url = base_url.rstrip('/')
        self.token: Optional[str] = None
        self.timeout = timeout
        self.verify = verify
        self.session = requests.Session()
        self._domain = urlparse(self.base_url).hostname or ''
        if self._domain.endswith('.'):
            self._domain = self._domain[:-1]

    # --- Internal helpers --------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        headers = {
            'Accept': 'application/json',
        }
        # If we have a session token (obtained via username/password login),
        # include it as a Bearer token for BHCE API authentication.
        if self.token:
            tok = str(self.token)
            headers['Authorization'] = tok if tok.lower().startswith('bearer ') else f'Bearer {tok}'
        return headers

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None):
        url = f"{self.base_url}{path}"
        return self.session.get(url, headers=self._headers(), params=params, timeout=self.timeout, verify=self.verify)

    def _post(self, path: str, json: Optional[Dict[str, Any]] = None, extra_headers: Optional[Dict[str, str]] = None, allow_redirects: bool = True):
        url = f"{self.base_url}{path}"
        headers = self._headers()
        headers['Content-Type'] = 'application/json'
        if extra_headers:
            headers.update(extra_headers)
        return self.session.post(url, headers=headers, json=json, timeout=self.timeout, verify=self.verify, allow_redirects=allow_redirects)


    # --- Auth/session ------------------------------------------------------
    def login(self, username: str, secret: str, otp: Optional[str] = None) -> bool:
        """Login with username/secret; store server-issued session token if present.

        Uses /api/v2/login with login_method "secret". If no token is returned,
        falls back to checking cookie-based auth by calling /api/v2/self.
        """
        body: Dict[str, Any] = {"login_method": "secret", "username": username, "secret": secret}
        if otp:
            body["one_time_passcode"] = otp
        try:
            r = self._post('/api/v2/login', json=body, extra_headers={"Prefer": "0"}, allow_redirects=True)
        except Exception:
            return False
        data: Dict[str, Any] = {}
        try:
            if r.headers.get('Content-Type','').startswith('application/json'):
                data = r.json() or {}
        except Exception:
            data = {}
        token = (((data.get('data') or {}).get('session_token')) or data.get('session_token'))
        if r.status_code < 300 and token:
            self.token = token
            return self.get_self() is not None
        if r.status_code < 300 and not token:
            # possibly cookie auth; verify
            return self.get_self() is not None
        return False

    def get_self(self) -> Optional[Dict[str, Any]]:
        try:
            r = self._get('/api/v2/self')
            if r.status_code < 300:
                try:
                    return r.json()
                except Exception:
                    return {}
        except Exception:
            pass
        return None

    # --- Direct REST: users -------------------------------------------------
    def get_users(self, page: int = 1, page_size: int = 100, counts: bool = False) -> Optional[Dict[str, Any]]:
        params = {
            'page': page,
            'page_size': page_size,
        }
        if counts:
            params['counts'] = 'true'
        try:
            r = self._get('/api/v2/users', params=params)
            if r.status_code < 300:
                return r.json()
        except Exception:
            pass
        return None

    def get_user(self, user_id: str, counts: bool = False) -> Optional[Dict[str, Any]]:
        path = f"/api/v2/users/{user_id}"
        params = {}
        if counts:
            params['counts'] = 'true'
        try:
            url = f"{self.base_url}{path}"
            headers = self._headers()
            headers['Prefer'] = '0'
            r = self.session.get(url, headers=headers, params=params, timeout=self.timeout, verify=self.verify)
            if r.status_code < 300:
                return r.json()
        except Exception:
            pass
        return None

    # --- Cypher query endpoint --------------------------------------------
    def cypher(self, query: str, include_properties: bool = True) -> Optional[Dict[str, Any]]:
        try:
            r = self._post('/api/v2/graphs/cypher', json={"query": query, "include_properties": include_properties})
            if r.status_code < 300:
                # Read JSON if present; for mutation queries the body may be empty
                try:
                    data = r.json()
                    if data:
                        return data
                except Exception:
                    pass
                # Return a minimal truthy object to indicate success on 2xx
                return {"ok": True, "status": r.status_code}
        except Exception:
            pass
        return None

    # --- Helpers built on cypher ------------------------------------------
    @staticmethod
    def _extract_nodes(graph_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        data = (graph_response or {}).get('data') or {}
        nodes = data.get('nodes') or {}
        out: List[Dict[str, Any]] = []
        for node_id, node in nodes.items():
            props = node.get('properties') or {}
            merged = {"id": node_id, **{k: v for k, v in node.items() if k != 'properties'}, "properties": props}
            if 'name' not in merged:
                merged['name'] = props.get('name')
            if 'objectid' not in merged:
                merged['objectid'] = props.get('objectid') or props.get('objectId')
            out.append(merged)
        return out

    def list_users(self, enabled: Optional[bool] = None) -> List[Dict[str, Any]]:
        where = " WHERE u.enabled=true" if enabled is True else (" WHERE u.enabled=false" if enabled is False else "")
        q = f"MATCH (u:User){where} RETURN u LIMIT 100000"
        resp = self.cypher(q, include_properties=True)
        if not resp:
            return []
        return self._extract_nodes(resp)


    def find_user_by_name_or_rid(self, username: str, rid: Optional[str]) -> Optional[Dict[str, Any]]:
        """Find a user by SAM@DOMAIN prefix plus RID suffix, with fallback to exact name.

        - Input username may be in the form DOMAIN\\USER or USER@DOMAIN.
        - Prefer matching nodes where u.name STARTS WITH 'SAM@' AND u.objectid ends with '-RID'.
        - Fallback to exact u.name match.
        """
        raw_user = username or ''
        # Derive SAM from either DOMAIN\\SAM or SAM@DOMAIN
        if '@' in raw_user:
            sam = raw_user.split('@', 1)[0]
        elif '\\' in raw_user:
            sam = raw_user.split('\\', 1)[1]
        else:
            sam = raw_user

        safe_user = raw_user.replace('\\', '\\\\').replace("'", "\\'")
        safe_sam = sam.replace('\\', '\\\\').replace("'", "\\'")

        if rid:
            safe_rid = str(rid).replace("'", "").upper()
            q = (
                "MATCH (u:User) WHERE toUpper(u.name) STARTS WITH toUpper('" + safe_sam + "@') "
                f"AND toUpper(u.objectid) ENDS WITH '-{safe_rid}' RETURN u LIMIT 1"
            )
        else:
            q = f"MATCH (u:User) WHERE toUpper(u.name) = toUpper('{safe_user}') RETURN u LIMIT 1"

        resp = self.cypher(q, include_properties=True)
        if not resp:
            return None
        nodes = self._extract_nodes(resp)
        if nodes:
            return nodes[0]
        # Fallback: ignore name and just match RID suffix, picking PHANTOM domains first
        if rid:
            q2 = f"MATCH (u:User) WHERE toUpper(u.objectid) ENDS WITH '-{safe_rid}' RETURN u LIMIT 5"
            resp2 = self.cypher(q2, include_properties=True)
            nodes2 = self._extract_nodes(resp2) if resp2 else []
            return nodes2[0] if nodes2 else None
        return None

    def update_user_properties(self, user: Dict[str, Any], props: Dict[str, Any]) -> bool:
        props = dict(props or {})
        objid = (
            user.get('objectId')
            or user.get('objectid')
            or (user.get('properties') or {}).get('objectid')
            or (user.get('properties') or {}).get('objectId')
        )
        name = user.get('name') or (user.get('properties') or {}).get('name')
        if not (objid or name):
            return False

        def _fmt(v: Any) -> str:
            if v is None:
                return 'null'
            if isinstance(v, bool):
                return 'true' if v else 'false'
            s = str(v).replace('\\', '\\\\').replace("'", "\\'")
            return f"'{s}'"

        assignments: List[str] = [f"u.{k} = {_fmt(v)}" for k, v in props.items()]
        if not assignments:
            return True
        where = f"u.objectid = '{objid}'" if objid else f"toUpper(u.name) = toUpper('{name.replace("'", "\\'")}')"
        q = f"MATCH (u:User) WHERE {where} SET {', '.join(assignments)} RETURN u LIMIT 1"
        try:
            r = self._post('/api/v2/graphs/cypher', json={"query": q, "include_properties": False})
            return r.status_code < 300
        except Exception:
            return False

    def update_node_properties_by_name(self, name: str, props: Dict[str, Any]) -> bool:
        """Generic helper: update arbitrary node by name with provided properties.

        Returns True on any non-error response from the API.
        """
        if not name:
            return False

        def _fmt(v: Any) -> str:
            if v is None:
                return 'null'
            if isinstance(v, bool):
                return 'true' if v else 'false'
            s = str(v).replace('\\', '\\\\').replace("'", "\\'")
            return f"'{s}'"

        props = dict(props or {})
        if not props:
            return True
        sets: List[str] = [f"n.{k} = {_fmt(v)}" for k, v in props.items()]
        safe_name = name.replace('\\', '\\\\').replace("'", "\\'")
        q = f"MATCH (n) WHERE toUpper(n.name) = toUpper('{safe_name}') SET {', '.join(sets)} RETURN n LIMIT 1"
        try:
            r = self._post('/api/v2/graphs/cypher', json={"query": q, "include_properties": False})
            return r.status_code < 300
        except Exception:
            return False
