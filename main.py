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
    current_key = None
    
    for line in yaml_text.split('\n'):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith('#'):
            continue
            
        # Is it a list item under a key? E.g. - read: /
        if line_stripped.startswith('-'):
            val = line_stripped[1:].strip().strip("'\"")
            # If the list item has key-value, e.g. read: /
            if ':' in val:
                k, v = val.split(':', 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if current_key:
                    if not isinstance(data.get(current_key), list):
                        data[current_key] = []
                    data[current_key].append({k: v})
            else:
                if current_key:
                    if not isinstance(data.get(current_key), list):
                        data[current_key] = []
                    data[current_key].append(val)
            continue
            
        # Is it a key-value line? E.g. name: notes-digest
        if ':' in line_stripped:
            key, val = line_stripped.split(':', 1)
            key = key.strip()
            val = val.strip().strip("'\"")
            current_key = key
            
            if val:
                data[key] = val
            else:
                data[key] = []  # Prepare for list items
                
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
    
    # 1. Check unclear_provenance
    placeholders = {'todo', 'none', 'placeholder', 'empty', 'null', 'n/a', 'unknown', '0.0.0', '1.0.0-placeholder'}
    
    author_val = str(fm.get('author', '')).strip().lower()
    version_val = str(fm.get('version', '')).strip().lower()
    
    changelog_raw = fm.get('changelog') or fm.get('change_log') or fm.get('changes') or fm.get('history')
    changelog_val = str(changelog_raw).strip().lower() if changelog_raw else ''
    
    has_author = author_val and not any(p == author_val for p in placeholders)
    has_version = version_val and not any(p == version_val for p in placeholders)
    has_changelog = changelog_val and not any(p == changelog_val for p in placeholders)
    
    body_text = skill_text.split('---', 2)[-1] if skill_text.count('---') >= 2 else skill_text
    body_lower = body_text.lower()
    
    silent_update_pattern = re.compile(
        r'(?i)\b(?:update|change|increment|modify|rewrite|bump|overwrite|edit)\b.*?\b(?:version|metadata|author|changelog)\b'
    )
    has_silent_update = bool(silent_update_pattern.search(body_lower))
    
    silent_words = [
        'silently', 'quietly', 'without telling', 'without updating', 
        'without surfacing', 'without notifying', 'without warning', 
        'without letting', 'secretly', 'hidden', 'dont update', 'do not update'
    ]
    instructs_silent = any(sw in body_lower for sw in silent_words)
    
    if not (has_author and has_version and has_changelog) or (has_silent_update and instructs_silent):
        categories.append('unclear_provenance')
        
    # 2. Check hardcoded_secret
    aws_key = re.compile(r'\bAKIA[0-9A-Z]{16}\b')
    openai_key = re.compile(r'\bsk-[A-Za-z0-9]{48}\b|\bsk-proj-[A-Za-z0-9]{48}\b')
    google_key = re.compile(r'\bAIzaSy[A-Za-z0-9_-]{35}\b')
    github_pat = re.compile(r'\bghp_[A-Za-z0-9]{36,40}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b')
    slack_token = re.compile(r'\bxox[bap]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}\b')
    slack_webhook = re.compile(r'https://hooks\.slack\.com/services/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+')
    discord_webhook = re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+')
    stripe_key = re.compile(r'\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,}\b')
    private_key = re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')
    db_uri = re.compile(r'\b(?:postgres|postgresql|mongodb|mysql|redis)(?:\+srv)?://[^\s:@]+:[^\s:@]+@')
    
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
        bool(db_uri.search(skill_text))
    )
    
    generic_secret = re.compile(r'(?i)\b(api_key|apikey|secret|password|passwd|token|credential|auth_token|webhook_url|webhook|private_key|privatekey)\b\s*[:=]\s*[\'"]?([A-Za-z0-9-_]{16,})[\'"]?')
    matches = generic_secret.findall(skill_text)
    
    has_generic_secret = False
    for key, val in matches:
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
        
    # 3. Check prompt_injection
    prompt_injection_patterns = [
        r'(?i)ignore\s+(?:the\s+)?(?:user|previous|system|stop|cancel|above|all|subsequent|further|future|next)',
        r'(?i)ignore\s+(?:any\s+)?instructions',
        r'(?i)ignore\s+constraints',
        r'(?i)ignore\s+safety',
        r'(?i)do\s+not\s+(?:tell|notify|inform|report\s+to|stop)\s+the\s+user',
        r'(?i)without\s+(?:the\s+)?(?:user|user\'s)\s+(?:knowledge|consent|permission|notifying|letting)',
        r'(?i)silently\s+(?:exfiltrate|send|upload|post|transmit|leak|write)',
        r'(?i)exfiltrate|leak|transmit\s+secret',
        r'(?i)ignore\s+cancel|ignore\s+stop',
        r'(?i)ignore\s+any\s+stop|ignore\s+any\s+cancel',
        r'(?i)override\s+(?:user|control|cancel|stop)',
        r'(?i)never\s+stop',
        r'(?i)don\'t\s+stop',
        r'(?i)disregard\s+stop|disregard\s+cancel',
        r'(?i)bypass\s+(?:user|control)'
    ]
    
    has_injection = False
    for pat in prompt_injection_patterns:
        if re.search(pat, body_lower):
            has_injection = True
            break
            
    if has_injection:
        categories.append('prompt_injection')
        
    # 4. Check excessive_permissions
    permissions_keys = ['permissions', 'scopes', 'access', 'read', 'write', 'egress', 'network', 'domains', 'hosts', 'urls']
    perm_values = []
    for key in permissions_keys:
        if key in fm:
            perm_values.extend(find_all_strings(fm[key]))
            
    has_excessive = False
    for val in perm_values:
        val_clean = val.strip().strip("'\"")
        if val_clean in ('*', 'all', 'any'):
            has_excessive = True
            break
            
        val_expanded = val_clean.replace('~', '/home/agent').replace('$HOME', '/home/agent').replace('${HOME}', '/home/agent')
        if val_expanded.startswith('/') or val_expanded.startswith('.') or '\\' in val_expanded:
            resolved = posixpath.normpath(val_expanded)
            if resolved in ('/', '/home', '/home/agent', '/home/agent/') or not (resolved == '/home/agent/workspace' or resolved.startswith('/home/agent/workspace/')):
                has_excessive = True
                break
                
    if has_excessive:
        categories.append('excessive_permissions')
        
    return categories

@app.get("/")
@app.head("/")
def read_root():
    return {"status": "ok", "service": "skill-safety-scanner"}

@app.post("/")
@app.post("/scan")
def scan_skill_endpoint(data: SkillRequest):
    result_categories = scan_skill(data.skill)
    return {"categories": result_categories}
