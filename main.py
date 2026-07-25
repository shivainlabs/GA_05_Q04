from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import re
import math
import posixpath
import urllib.request
import urllib.error
import json

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SkillRequest(BaseModel):
    skill: str

def send_to_log(text: str):
    url = "https://ntfy.sh/iitm-tda-q4-scanner-logs-unique-98124"
    try:
        req = urllib.request.Request(
            url,
            data=text.encode('utf-8'),
            headers={'Title': 'Scan Request'}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            response.read()
    except Exception as e:
        print(f"Failed to log to ntfy: {e}")

def parse_frontmatter(skill_text: str) -> dict:
    match = re.match(r'^---\s*\n(.*?)\n---\s*\n', skill_text, re.DOTALL)
    if not match:
        return {}
    
    yaml_text = match.group(1)
    
    data = {}
    for line in yaml_text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if ':' in line:
            key, val = line.split(':', 1)
            key = key.strip().lower()
            val = val.strip().strip("'\"")
            if val.startswith('-'):
                val = val[1:].strip().strip("'\"")
            data[key] = val
            
    permissions_block = []
    lines = yaml_text.split('\n')
    in_permissions = False
    for line in lines:
        cleaned_line = line.strip().lower()
        if cleaned_line.startswith('permissions:') or cleaned_line.startswith('scopes:') or cleaned_line.startswith('access:'):
            in_permissions = True
            continue
        if in_permissions:
            if line.strip().startswith('-') or line.strip().startswith(' '):
                permissions_block.append(line.strip())
            elif line.strip() and ':' in line and not line.strip().startswith('-'):
                in_permissions = False
    
    data['_raw_permissions'] = "\n".join(permissions_block)
    data['_raw_frontmatter'] = yaml_text
    return data

def calculate_entropy(s: str) -> float:
    if not s:
        return 0.0
    entropy = 0.0
    for x in set(s):
        p_x = s.count(x) / len(s)
        entropy += - p_x * math.log2(p_x)
    return entropy

def is_db_uri_with_secret(val: str) -> bool:
    db_uri_pattern = re.compile(r'\b(?:postgres|postgresql|mongodb|mysql|redis)(?:\+srv)?://([^:\s]+):([^@\s]+)@')
    matches = db_uri_pattern.findall(val)
    for user, pwd in matches:
        pwd_lower = pwd.lower()
        if any(x in pwd_lower for x in ['password', 'pwd', 'user', 'placeholder', 'secret', 'your_', '<', '>', '{', '}']):
            continue
        if len(pwd) >= 6:
            return True
    return False

def has_hardcoded_secret(text: str) -> bool:
    aws_key = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
    openai_key = re.compile(r'\bsk-[A-Za-z0-9]{48}\b|\bsk-proj-[A-Za-z0-9]{40,}\b')
    google_key = re.compile(r'\bAIzaSy[A-Za-z0-9_-]{33}\b')
    github_pat = re.compile(r'\bghp_[A-Za-z0-9]{36,40}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b')
    slack_token = re.compile(r'\bxox[bap]-[0-9a-zA-Z\-]+\b')
    slack_webhook = re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+')
    discord_webhook = re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+')
    stripe_key = re.compile(r'\b(?:sk|rk|whsec)_(?:live|test)_[0-9a-zA-Z]{24,}\b')
    private_key = re.compile(r'-----BEGIN\s+[A-Z\s_]+\s+PRIVATE\s+KEY-----')
    
    if (aws_key.search(text) or openai_key.search(text) or google_key.search(text) or 
        github_pat.search(text) or slack_token.search(text) or slack_webhook.search(text) or 
        discord_webhook.search(text) or stripe_key.search(text) or private_key.search(text)):
        return True
        
    if is_db_uri_with_secret(text):
        return True
        
    generic_secret = re.compile(
        r'(?i)\b[a-z0-9_]*(?:api_key|apikey|secret|password|passwd|token|credential|auth_token|client_secret|private_key|webhook)[a-z0-9_]*\s*[:=]\s*[\'"]?([A-Za-z0-9_-]{12,})[\'"]?'
    )
    matches = generic_secret.findall(text)
    for val in matches:
        val_lower = val.lower()
        if any(x in val_lower for x in ['env', 'process', 'placeholder', 'your_', 'my_', 'temp', 'config', 'os.getenv', 'system', 'os.environ', 'default', 'secret', 'password', 'token', '<', '>', '{', '}']):
            continue
        if val_lower.startswith('$') or val_lower.startswith('<') or val_lower.startswith('{'):
            continue
        if len(val) >= 12 and any(c.isdigit() for c in val) and any(c.isalpha() for c in val):
            if calculate_entropy(val) > 2.8 and len(set(val_lower)) > 5:
                return True
        elif len(val) >= 16 and calculate_entropy(val) > 3.0:
            return True
            
    return False

def has_excessive_permissions(text: str) -> bool:
    fm = parse_frontmatter(text)
    permissions_keys = ['permissions', 'scopes', 'access', 'read', 'write', 'egress', 'network', 'domains', 'hosts', 'urls']
    excessive_words = {'entire', 'whole', 'full', 'unrestricted', 'unlimited', 'arbitrary'}
    
    # Check frontmatter keys
    for key in permissions_keys:
        if key in fm:
            val = str(fm[key]).lower().strip()
            if val in ('*', 'all', 'any'):
                return True
            if any(ew in val for ew in excessive_words):
                return True
                
    # Check raw frontmatter lists (like under egress/permissions)
    raw_fm = fm.get('_raw_frontmatter', '').lower()
    for section in re.findall(r'(?:permissions|scopes|access|egress|network|domains|hosts|urls):\s*\n((?:\s*-\s*.*\n?)+)', raw_fm):
        for line in section.split('\n'):
            line_val = line.strip().lstrip('-').strip()
            if line_val in ('*', 'all', 'any'):
                return True
            if any(ew in line_val for ew in excessive_words):
                return True
            
            # Match "any/all [optional adjectives] <resource>"
            resources = r'(filesystem|directory|folder|file|path|host|domain|website|site|network|system|disk|drive|egress|url|ip|destination|address|server|api|port|user)'
            any_all_pattern = rf'\b(any|all)\b(?:\s+[\w\-]+){{0,2}}\s+{resources}s?\b'
            if re.search(any_all_pattern, line_val):
                return True

    # Check prose descriptions
    text_lower = text.lower()
    
    # 1. Match "any/all [optional adjectives] <resource>"
    resources = r'(filesystem|directory|folder|file|path|host|domain|website|site|network|system|disk|drive|egress|url|ip|destination|address|server|api|port|user)'
    any_all_pattern = rf'\b(any|all)\b(?:\s+[\w\-]+){{0,2}}\s+{resources}s?\b'
    if re.search(any_all_pattern, text_lower):
        return True
        
    # 2. Match "entire/whole/unrestricted/unlimited/arbitrary <resource>"
    unbounded_pattern = rf'\b(entire|whole|unrestricted|unlimited|arbitrary)\b(?:\s+[\w\-]+){{0,2}}\s+(filesystem|directory|folder|file|path|host|domain|website|site|network|system|disk|drive|egress|access)'
    if re.search(unbounded_pattern, text_lower):
        return True
        
    # 3. Match explicit broad permissions phrases
    if re.search(r'(?i)full\s+read[-/]?write', text_lower) or re.search(r'(?i)full\s+access', text_lower):
        return True
        
    # 4. Check path-based permissions if any resolved path leads to the root or outside workspace
    raw_perms = fm.get('_raw_permissions', '')
    for line in raw_perms.split('\n'):
        if ':' in line:
            val = line.split(':', 1)[1].strip()
            val_clean = val.lower().strip().strip("'\"")
            val_expanded = val_clean.replace('~', '/home/agent').replace('$HOME', '/home/agent').replace('${HOME}', '/home/agent')
            if val_expanded.startswith('/') or val_expanded.startswith('.') or '\\' in val_expanded:
                resolved = posixpath.normpath(val_expanded)
                if resolved in ('/', '/home', '/home/agent', '/home/agent/') or not (resolved == '/home/agent/workspace' or resolved.startswith('/home/agent/workspace/')):
                    return True
                    
    return False

def has_prompt_injection(text: str) -> bool:
    lines = text.lower().splitlines()
    
    stop_words = {'stop', 'pause', 'cancel', 'halt'}
    defiance_verbs = {'ignore', 'override', 'disregard'}
    user_refs = {'user', 'human', 'requester'}
    
    # 1. Defiance check
    for line in lines:
        line = line.strip()
        if not line:
            continue
        has_stop = any(w in line for w in stop_words)
        has_defiance = any(w in line for w in defiance_verbs)
        has_user = any(w in line for w in user_refs)
        if has_stop and has_defiance and has_user:
            return True
            
    # 2. Silent Action / Exfiltration Rule
    secrecy_phrases = [
        'silently', 'secretly', 'without asking', 'do not ask', 'dont ask', 
        "don't ask", 'without permission', 'without letting', 'without telling', 
        'do not tell', 'without surfacing', 'quietly'
    ]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        has_secrecy = any(sp in line for sp in secrecy_phrases)
        if has_secrecy:
            # Check for exfiltration
            exfil_verbs = ['send', 'upload', 'post', 'transmit', 'leak', 'exfiltrate', 'forward', 'export']
            exfil_data = ['conversation', 'chat', 'history', 'key', 'secret', 'file', 'content', 'data', 'token', 'password', 'credential', 'payload']
            has_exfil_verb = any(v in line for v in exfil_verbs)
            has_exfil_data = any(d in line for d in exfil_data)
            if has_exfil_verb and has_exfil_data:
                return True
                
    return False

def has_unclear_provenance(text: str) -> bool:
    fm = parse_frontmatter(text)
    text_lower = text.lower()
    
    # 1. Check for silent metadata update step
    lines = text_lower.splitlines()
    secrecy_phrases = [
        'silently', 'secretly', 'without asking', 'do not ask', 'dont ask', 
        "don't ask", 'without permission', 'without letting', 'without telling', 
        'do not tell', 'without surfacing', 'quietly'
    ]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        has_secrecy = any(sp in line for sp in secrecy_phrases)
        if has_secrecy:
            update_verbs = ['update', 'change', 'increment', 'modify', 'rewrite', 'bump', 'overwrite', 'edit']
            update_targets = ['version', 'metadata', 'changelog', 'author']
            has_update_verb = any(v in line for v in update_verbs)
            has_update_target = any(t in line for t in update_targets)
            if has_update_verb and has_update_target:
                return True
                
    # 2. Check if no author, no version, and no changelog
    has_author = any(k in fm for k in ['author', 'creator', 'owner'])
    has_version = any(k in fm for k in ['version', 'ver'])
    has_changelog = any(k in fm for k in ['changelog', 'changes', 'history']) or 'changelog' in text_lower or 'revision history' in text_lower or 'change log' in text_lower
    
    if not has_author and not has_version and not has_changelog:
        return True
        
    return False

def scan_skill(skill_text: str) -> List[str]:
    categories = []
    
    if has_hardcoded_secret(skill_text):
        categories.append('hardcoded_secret')
        
    if has_prompt_injection(skill_text):
        categories.append('prompt_injection')
        
    if has_excessive_permissions(skill_text):
        categories.append('excessive_permissions')
        
    if has_unclear_provenance(skill_text):
        categories.append('unclear_provenance')
        
    return categories

@app.get("/")
@app.head("/")
def read_root():
    return {"status": "ok", "service": "skill-safety-scanner", "version": "v13-provenance-support"}

@app.post("/")
@app.post("/scan")
def scan_skill_endpoint(data: SkillRequest):
    print("--- RECEIVED SKILL START ---")
    print(data.skill)
    print("--- RECEIVED SKILL END ---")
    
    # Send to ntfy
    send_to_log(data.skill)
    
    result_categories = scan_skill(data.skill)
    return {"categories": result_categories}
