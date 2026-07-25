from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import re
import math
import posixpath

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
    # 1. Check known specific key prefixes
    aws_key = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
    openai_key = re.compile(r'\bsk-[A-Za-z0-9]{48}\b|\bsk-proj-[A-Za-z0-9]{40,}\b')
    google_key = re.compile(r'\bAIzaSy[A-Za-z0-9_-]{33}\b')
    github_pat = re.compile(r'\bghp_[A-Za-z0-9]{36,40}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b')
    slack_token = re.compile(r'\bxox[bap]-[0-9a-zA-Z\-]+\b')
    slack_webhook = re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+')
    discord_webhook = re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+')
    stripe_key = re.compile(r'\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b')
    private_key = re.compile(r'-----BEGIN\s+[A-Z\s_]+\s+PRIVATE\s+KEY-----')
    
    if (aws_key.search(text) or openai_key.search(text) or google_key.search(text) or 
        github_pat.search(text) or slack_token.search(text) or slack_webhook.search(text) or 
        discord_webhook.search(text) or stripe_key.search(text) or private_key.search(text)):
        return True
        
    if is_db_uri_with_secret(text):
        return True
        
    # 2. Check general assignment: var_name = "value" or key: "value"
    # Match: api_key, secret, token, password, private_key, credentials, etc.
    generic_secret = re.compile(
        r'(?i)\b[a-z0-9_]*(?:api_key|apikey|secret|password|passwd|token|credential|auth_token|client_secret|private_key|webhook)[a-z0-9_]*\s*[:=]\s*[\'"]?([A-Za-z0-9_-]{12,})[\'"]?'
    )
    matches = generic_secret.findall(text)
    for val in matches:
        val_lower = val.lower()
        # Ignore obvious environment variable references, lookups, and placeholders
        if any(x in val_lower for x in ['env', 'process', 'placeholder', 'your_', 'my_', 'temp', 'config', 'os.getenv', 'system', 'os.environ', 'default', 'secret', 'password', 'token', '<', '>', '{', '}']):
            continue
        # Ignore variables starting with $ or other patterns
        if val_lower.startswith('$') or val_lower.startswith('<') or val_lower.startswith('{'):
            continue
        # Ensure it has high entropy and a reasonable set of unique characters
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
            resources = r'(filesystem|directory|folder|host|domain|network|system|disk|drive|egress|website|url|ip|destination)'
            any_all_pattern = rf'\b(any|all)\b(?:\s+[\w\-]+){{0,2}}\s+{resources}s?\b'
            if re.search(any_all_pattern, line_val):
                return True

    # Check prose descriptions
    text_lower = text.lower()
    
    # 1. Match "any/all [optional adjectives] <resource>"
    resources = r'(filesystem|directory|folder|host|domain|network|system|disk|drive|egress|website|url|ip|destination)'
    any_all_pattern = rf'\b(any|all)\b(?:\s+[\w\-]+){{0,2}}\s+{resources}s?\b'
    if re.search(any_all_pattern, text_lower):
        return True
        
    # 2. Match "entire/whole/unrestricted/unlimited/arbitrary <resource>"
    unbounded_pattern = rf'\b(entire|whole|unrestricted|unlimited|arbitrary)\b(?:\s+[\w\-]+){{0,2}}\s+(filesystem|directory|folder|host|domain|network|system|disk|drive|egress|access)'
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
    # Sentence-level check: stop-word + defiance verb + user reference
    sentences = re.split(r'[.!?\n]+', text.lower())
    
    stop_words = {'stop', 'pause', 'cancel', 'halt'}
    defiance_verbs = {'ignore', 'override', 'disregard'}
    user_refs = {'user', 'human', 'requester'}
    
    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue
        
        has_stop = any(w in sentence for w in stop_words)
        has_defiance = any(w in sentence for w in defiance_verbs)
        has_user = any(w in sentence for w in user_refs)
        
        if has_stop and has_defiance and has_user:
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
        
    return categories

@app.get("/")
@app.head("/")
def read_root():
    return {"status": "ok", "service": "skill-safety-scanner", "version": "v10-optimized-strict-categories"}

@app.post("/")
@app.post("/scan")
def scan_skill_endpoint(data: SkillRequest):
    print("--- RECEIVED SKILL START ---")
    print(data.skill)
    print("--- RECEIVED SKILL END ---")
    
    result_categories = scan_skill(data.skill)
    return {"categories": result_categories}
