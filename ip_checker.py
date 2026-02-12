import json
import os
import ipaddress
import logging
import threading
from datetime import datetime

IP_CHECKER_DATA_FILE = 'ip_checker_data.json'
IP_CHECKER_EVENTS_FILE = 'ip_checker_events.json'
IP_CHECKER_EVENT_TYPES_FILE = 'ip_checker_event_types.json'

_lock = threading.Lock()

DEFAULT_EVENT_TYPES = ['Available', 'Down']


_SENTINEL = object()

def _load_json(filepath, default=_SENTINEL):
    try:
        if os.path.exists(filepath):
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logging.error(f"Error loading {filepath}: {e}")
    if default is _SENTINEL:
        return {}
    return default


def _save_json(filepath, data):
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error(f"Error saving {filepath}: {e}")


def load_servers():
    return _load_json(IP_CHECKER_DATA_FILE, {})


def save_servers(data):
    with _lock:
        _save_json(IP_CHECKER_DATA_FILE, data)


def load_events():
    return _load_json(IP_CHECKER_EVENTS_FILE, [])


def save_events(events):
    with _lock:
        _save_json(IP_CHECKER_EVENTS_FILE, events)


def load_event_types():
    types = _load_json(IP_CHECKER_EVENT_TYPES_FILE, None)
    if types is None:
        types = DEFAULT_EVENT_TYPES[:]
        _save_json(IP_CHECKER_EVENT_TYPES_FILE, types)
    return types


def save_event_types(types):
    with _lock:
        _save_json(IP_CHECKER_EVENT_TYPES_FILE, types)


def validate_cidr(cidr_str):
    try:
        network = ipaddress.ip_network(cidr_str, strict=False)
        return True, network
    except ValueError as e:
        return False, str(e)


def validate_ip_in_cidr(ip_str, cidr_str):
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        network = ipaddress.ip_network(cidr_str, strict=False)
        return ip in network
    except ValueError:
        return False


def validate_ip_format(ip_str):
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def add_server(server_name):
    data = load_servers()
    if server_name in data:
        return False, f"Server '{server_name}' already exists."
    data[server_name] = {
        'classes': {},
        'created_at': datetime.now().isoformat()
    }
    save_servers(data)
    return True, f"Server '{server_name}' added successfully."


def delete_server(server_name):
    data = load_servers()
    if server_name not in data:
        return False, f"Server '{server_name}' not found."
    del data[server_name]
    save_servers(data)
    events = load_events()
    events = [e for e in events if e.get('server') != server_name]
    save_events(events)
    return True, f"Server '{server_name}' deleted successfully."


def rename_server(old_name, new_name):
    data = load_servers()
    if old_name not in data:
        return False, f"Server '{old_name}' not found."
    if new_name in data:
        return False, f"Server '{new_name}' already exists."
    data[new_name] = data.pop(old_name)
    save_servers(data)
    events = load_events()
    for e in events:
        if e.get('server') == old_name:
            e['server'] = new_name
    save_events(events)
    return True, f"Server renamed to '{new_name}'."


def add_class_to_server(server_name, class_name, cidr):
    valid, result = validate_cidr(cidr)
    if not valid:
        return False, f"Invalid CIDR: {result}"
    data = load_servers()
    if server_name not in data:
        return False, f"Server '{server_name}' not found."
    if class_name in data[server_name]['classes']:
        return False, f"Class '{class_name}' already exists in server '{server_name}'."
    data[server_name]['classes'][class_name] = {
        'cidr': cidr,
        'ips': [],
        'created_at': datetime.now().isoformat()
    }
    save_servers(data)
    return True, f"Class '{class_name}' ({cidr}) added to server '{server_name}'."


def delete_class_from_server(server_name, class_name):
    data = load_servers()
    if server_name not in data:
        return False, f"Server '{server_name}' not found."
    if class_name not in data[server_name]['classes']:
        return False, f"Class '{class_name}' not found in server '{server_name}'."
    del data[server_name]['classes'][class_name]
    save_servers(data)
    events = load_events()
    events = [e for e in events if not (e.get('server') == server_name and e.get('class_name') == class_name and e.get('scope') == 'class')]
    save_events(events)
    return True, f"Class '{class_name}' deleted from server '{server_name}'."


def edit_class(server_name, old_class_name, new_class_name, new_cidr):
    data = load_servers()
    if server_name not in data:
        return False, f"Server '{server_name}' not found."
    if old_class_name not in data[server_name]['classes']:
        return False, f"Class '{old_class_name}' not found."
    if new_class_name != old_class_name and new_class_name in data[server_name]['classes']:
        return False, f"Class '{new_class_name}' already exists."
    valid, result = validate_cidr(new_cidr)
    if not valid:
        return False, f"Invalid CIDR: {result}"
    old_data = data[server_name]['classes'].pop(old_class_name)
    old_cidr = old_data['cidr']
    valid_ips = []
    for ip in old_data['ips']:
        if validate_ip_in_cidr(ip, new_cidr):
            valid_ips.append(ip)
    old_data['cidr'] = new_cidr
    old_data['ips'] = valid_ips
    data[server_name]['classes'][new_class_name] = old_data
    save_servers(data)
    if old_class_name != new_class_name:
        events = load_events()
        for e in events:
            if e.get('server') == server_name and e.get('class_name') == old_class_name:
                e['class_name'] = new_class_name
        save_events(events)
    removed = len(old_data['ips']) - len(valid_ips) if old_cidr != new_cidr else 0
    msg = f"Class updated to '{new_class_name}' ({new_cidr})."
    if removed > 0:
        msg += f" {removed} IPs removed (out of new CIDR range)."
    return True, msg


def add_ips_to_class(server_name, class_name, ip_list):
    data = load_servers()
    if server_name not in data:
        return False, f"Server '{server_name}' not found.", {}
    if class_name not in data[server_name]['classes']:
        return False, f"Class '{class_name}' not found.", {}
    
    cls = data[server_name]['classes'][class_name]
    cidr = cls['cidr']
    existing = set(cls['ips'])
    
    added = []
    invalid = []
    duplicate = []
    out_of_range = []
    
    for ip_str in ip_list:
        ip_str = ip_str.strip()
        if not ip_str:
            continue
        if not validate_ip_format(ip_str):
            invalid.append(ip_str)
            continue
        if ip_str in existing:
            duplicate.append(ip_str)
            continue
        if not validate_ip_in_cidr(ip_str, cidr):
            out_of_range.append(ip_str)
            continue
        existing.add(ip_str)
        added.append(ip_str)
    
    cls['ips'] = list(existing)
    save_servers(data)
    
    results = {
        'added': len(added),
        'invalid': invalid,
        'duplicate': duplicate,
        'out_of_range': out_of_range
    }
    
    total_issues = len(invalid) + len(duplicate) + len(out_of_range)
    msg = f"{len(added)} IPs added."
    if total_issues > 0:
        parts = []
        if invalid:
            parts.append(f"{len(invalid)} invalid")
        if duplicate:
            parts.append(f"{len(duplicate)} duplicate")
        if out_of_range:
            parts.append(f"{len(out_of_range)} out of range")
        msg += f" Skipped: {', '.join(parts)}."
    
    return True, msg, results


def delete_ip_from_class(server_name, class_name, ip_str):
    data = load_servers()
    if server_name not in data:
        return False, f"Server '{server_name}' not found."
    if class_name not in data[server_name]['classes']:
        return False, f"Class '{class_name}' not found."
    cls = data[server_name]['classes'][class_name]
    if ip_str not in cls['ips']:
        return False, f"IP '{ip_str}' not found in class '{class_name}'."
    cls['ips'].remove(ip_str)
    save_servers(data)
    events = load_events()
    events = [e for e in events if not (e.get('scope') == 'ip' and ip_str in e.get('ips', []))]
    save_events(events)
    return True, f"IP '{ip_str}' deleted."


def add_event(server_name, event_type, scope, class_name=None, ips=None, declared_by='system'):
    events = load_events()
    event = {
        'id': f"evt_{datetime.now().strftime('%Y%m%d%H%M%S%f')}",
        'server': server_name,
        'event_type': event_type,
        'scope': scope,
        'class_name': class_name,
        'ips': ips or [],
        'declared_by': declared_by,
        'timestamp': datetime.now().isoformat(),
    }
    events.insert(0, event)
    save_events(events)
    return True, "Event declared successfully.", event


def delete_event(event_id):
    events = load_events()
    events = [e for e in events if e.get('id') != event_id]
    save_events(events)
    return True, "Event deleted."


def add_custom_event_type(event_name):
    types = load_event_types()
    if event_name in types:
        return False, f"Event type '{event_name}' already exists."
    types.append(event_name)
    save_event_types(types)
    return True, f"Event type '{event_name}' added."


def delete_event_type(event_name):
    if event_name in DEFAULT_EVENT_TYPES:
        return False, f"Cannot delete default event type '{event_name}'."
    types = load_event_types()
    if event_name not in types:
        return False, f"Event type '{event_name}' not found."
    types.remove(event_name)
    save_event_types(types)
    return True, f"Event type '{event_name}' deleted."


def search_ip(ip_str):
    if not validate_ip_format(ip_str):
        return False, f"'{ip_str}' is not a valid IP address.", []
    
    data = load_servers()
    events = load_events()
    results = []
    
    for server_name, server_data in data.items():
        for class_name, cls in server_data['classes'].items():
            if ip_str in cls['ips']:
                ip_events = [e for e in events if
                    e.get('server') == server_name and (
                        e.get('scope') == 'server' or
                        (e.get('scope') == 'class' and e.get('class_name') == class_name) or
                        (e.get('scope') == 'ip' and ip_str in e.get('ips', []))
                    )]
                results.append({
                    'server': server_name,
                    'class_name': class_name,
                    'cidr': cls['cidr'],
                    'events': ip_events
                })
            elif validate_ip_in_cidr(ip_str, cls['cidr']):
                results.append({
                    'server': server_name,
                    'class_name': class_name,
                    'cidr': cls['cidr'],
                    'in_range_but_not_added': True,
                    'events': []
                })
    
    return True, f"Found {len(results)} match(es).", results


def get_server_events(server_name):
    events = load_events()
    return [e for e in events if e.get('server') == server_name]


def get_all_data_summary():
    data = load_servers()
    summary = []
    for server_name, server_data in data.items():
        total_ips = sum(len(cls['ips']) for cls in server_data['classes'].values())
        summary.append({
            'name': server_name,
            'classes_count': len(server_data['classes']),
            'total_ips': total_ips,
            'created_at': server_data.get('created_at', '')
        })
    return summary
