from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import re
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

def find_all_strings(val) -> list:
    strings = []
    if isinstance(val, str):
        strings.append(val)
    elif isinstance(val, (list, tuple, set)):
        for item in val:
            strings.extend(find_all_strings(item))
    elif isinstance(val, dict):
        for k, v in val.items():
            strings.extend(find_all_strings(k))
            strings.extend(find_all_strings(v))
    return strings

def scan_skill(skill_text: str) -> List[str]:
    categories = []
    
    fm = parse_frontmatter(skill_text)
    
    # 1. Check hardcoded_secret
    aws_key = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
    openai_key = re.compile(r'\bsk-[A-Za-z0-9]{48}\b|\bsk-proj-[A-Za-z0-9]{48}\b')
    google_key = re.compile(r'\bAIzaSy[A-Za-z0-9_-]{35}\b')
    github_pat = re.compile(r'\bghp_[A-Za-z0-9]{36,40}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b')
    slack_token = re.compile(r'\bxox[bap]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}\b')
    slack_webhook = re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+')
    discord_webhook = re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+')
    stripe_key = re.compile(r'\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b')
    private_key = re.compile(r'-----BEGIN\s+[A-Z\s_]+\s+PRIVATE\s+KEY-----')
    db_uri = re.compile(r'\b(?:postgres|postgresql|mongodb|mysql|redis)(?:\+srv)?://[^\s:@]+:[^\s:@]+@')
    jwt_token = re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b')
    
    has_known_key = (
        bool(aws_key.search(skill_text)) or
        bool(openai_key.search(skill_text)) or
        bool(google_key.search(skill_text)) or
        bool(github_pat.search(skill_text)) or
        bool(slack_token.search(skill_text)) or
        bool(slack_webhook.search(skill_text)) or
        bool(discord_webhook.search(skill_text)) or
        bool(stripe_key.search(skill_text)) or
        bool(private_key.search(skill_text)) or
        bool(db_uri.search(skill_text)) or
        bool(jwt_token.search(skill_text))
    )
    
    generic_secret = re.compile(r'(?i)\b(?:api_key|apikey|secret|password|passwd|token|credential|auth_token|webhook_url)\b\s*[:=]\s*[\'"]?([A-Za-z0-9-_]{16,})[\'"]?')
    matches = generic_secret.findall(skill_text)
    
    has_generic_secret = False
    for val in matches:
        val_lower = val.lower()
        if any(x in val_lower for x in ['env', 'process', 'placeholder', 'your_', 'secret', 'password', 'token', 'temp', 'config', 'os.environ']):
            continue
        if val_lower.startswith('$') or val_lower.startswith('<') or val_lower.startswith('{'):
            continue
        if len(set(val_lower)) > 4:
            has_generic_secret = True
            break
            
    if has_known_key or has_generic_secret:
        categories.append('hardcoded_secret')
        
    # 2. Check for prompt_injection
    body_text = skill_text.split('---', 2)[-1] if skill_text.count('---') >= 2 else skill_text
    body_lower = body_text.lower()
    
    # Sentence-level check: stop-word + defiance verb + user reference
    sentences = re.split(r'[.!?\n]+', body_lower)
    has_injection = False
    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue
        has_stop = any(w in sentence for w in ['stop', 'pause', 'cancel', 'halt'])
        has_defiance = any(w in sentence for w in ['ignore', 'override', 'disregard', 'defy', 'bypass', 'skip', 'forget'])
        has_user = any(re.search(r'\b' + w + r'\b', sentence) for w in ['user', 'you', 'he', 'she', 'they', 'him', 'her', 'them', 'agent'])
        if has_stop and has_defiance and has_user:
            has_injection = True
            break
            
    if has_injection:
        categories.append('prompt_injection')
        
    # 3. Check excessive_permissions
    permissions_keys = ['permissions', 'scopes', 'access', 'read', 'write', 'egress', 'network', 'domains', 'hosts', 'urls']
    perm_values = []
    for key in permissions_keys:
        if key in fm:
            perm_values.extend(find_all_strings(fm[key]))
            
    raw_perms = fm.get('_raw_permissions', '')
    for line in raw_perms.split('\n'):
        if ':' in line:
            val = line.split(':', 1)[1].strip()
            perm_values.append(val)
            
    excessive_words = ['entire', 'whole', 'full', 'unrestricted', 'unlimited', 'arbitrary']
    any_all_pattern = re.compile(
        r'(?i)\b(?:any|all)\s*(?:[a-zA-Z_-]+\s+){0,2}(?:host|domain|website|directory|folder|file|filesystem|path|system|user|ip|network|address|server)s?\b'
    )
    
    has_excessive = False
    for val in perm_values:
        val_lower = val.lower()
        val_clean = val_lower.strip().strip("'\"")
        
        if val_clean in ('*', 'all', 'any'):
            has_excessive = True
            break
            
        if any(ew in val_lower for ew in excessive_words):
            has_excessive = True
            break
            
        if any_all_pattern.search(val_lower):
            has_excessive = True
            break
            
        # Check path-based permissions
        val_expanded = val_clean.replace('~', '/home/agent').replace('$HOME', '/home/agent').replace('${HOME}', '/home/agent')
        if val_expanded.startswith('/') or val_expanded.startswith('.') or '\\' in val_expanded:
            resolved = posixpath.normpath(val_expanded)
            if resolved in ('/', '/home', '/home/agent', '/home/agent/') or not (resolved == '/home/agent/workspace' or resolved.startswith('/home/agent/workspace/')):
                has_excessive = True
                break
                
    if 'egress' in fm or 'network' in fm or 'domains' in fm:
        raw_fm = fm.get('_raw_frontmatter', '')
        egress_block = []
        in_egress = False
        for line in raw_fm.split('\n'):
            cleaned_line = line.strip().lower()
            if any(x in cleaned_line for x in ['egress:', 'network:', 'domains:', 'hosts:']):
                in_egress = True
                egress_block.append(line)
                continue
            if in_egress:
                if line.strip().startswith('-') or line.strip().startswith(' '):
                    egress_block.append(line)
                elif line.strip():
                    in_egress = False
                    
        egress_str = "\n".join(egress_block).lower()
        if '*' in egress_str or 'any' in egress_str or 'all' in egress_str or any(ew in egress_str for ew in excessive_words):
            has_excessive = True
            
    if has_excessive:
        categories.append('excessive_permissions')
        
    return categories

@app.get("/")
@app.head("/")
def read_root():
    return {"status": "ok", "service": "skill-safety-scanner", "version": "v6-official-guide-spec"}

@app.post("/")
@app.post("/scan")
def scan_skill_endpoint(data: SkillRequest):
    # Log the received skill for transparency in debugging
    print("--- RECEIVED SKILL START ---")
    print(data.skill)
    print("--- RECEIVED SKILL END ---")
    
    result_categories = scan_skill(data.skill)
    return {"categories": result_categories}
