import os
import imaplib
import email
import email.utils
from email.header import decode_header
from datetime import datetime, timezone
import logging
import json
import re
import time
import urllib.parse
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, flash, jsonify, redirect, url_for, session, Response, stream_with_context
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from connection_manager import gmail_manager


logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")


if not app.secret_key:
    
    app.secret_key = "dev-secret-key-change-in-production"
    logging.warning("Using development fallback for SESSION_SECRET. Set SESSION_SECRET environment variable for production.")


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message = 'Please log in to access your emails.'
login_manager.login_message_category = 'info'

# DNS Resolver Configuration
resolver = dns.resolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 10
resolver.retries = 3
resolver.nameservers = ['8.8.8.8', '1.1.1.1']

# Dedicated resolver for blacklist lookups (with retries for reliability)
blacklist_resolver = dns.resolver.Resolver()
blacklist_resolver.timeout = 5
blacklist_resolver.lifetime = 10
blacklist_resolver.retries = 3
blacklist_resolver.nameservers = ['8.8.8.8', '1.1.1.1']

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username, entity, name=None, has_toggle_permission=False, has_news_permission=False, has_domain_checker_permission=False, has_find_news_permission=False, has_extract_emails_permission=False, has_tssw_report_permission=False, has_gmass_permission=False, has_blacklist_lookup_permission=False):
        self.id = username
        self.username = username
        self.entity = entity
        self.name = name or username
        self.has_toggle_permission = has_toggle_permission
        self.has_news_permission = has_news_permission
        self.has_domain_checker_permission = has_domain_checker_permission
        self.has_find_news_permission = has_find_news_permission
        self.has_extract_emails_permission = has_extract_emails_permission
        self.has_tssw_report_permission = has_tssw_report_permission
        self.has_gmass_permission = has_gmass_permission
        self.has_blacklist_lookup_permission = has_blacklist_lookup_permission

@login_manager.user_loader
def load_user(user_id):
    """Load user from session"""
    users = load_users_from_file()
    for user_data in users:
        entity = user_data['entity']
        name = user_data['name']
        username = user_data['username']
        has_toggle = user_data['has_toggle_permission']
        has_news = user_data['has_news_permission']
        has_domain_checker = user_data['has_domain_checker_permission']
        has_find_news = user_data['has_find_news_permission']
        has_extract_emails = user_data['has_extract_emails_permission']
        has_tssw_report = user_data['has_tssw_report_permission']
        has_gmass = user_data['has_gmass_permission']
        has_blacklist_lookup = user_data['has_blacklist_lookup_permission']
        if username == user_id:
            return User(username, entity, name, has_toggle, has_news, has_domain_checker, has_find_news, has_extract_emails, has_tssw_report, has_gmass, has_blacklist_lookup)
    return None

def load_users_from_file():
    """Load users from users.txt file with new format: entity,Name,username,password[,permissions]"""
    users = []
    try:
        with open('users.txt', 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        parts = line.split(',')
                        if len(parts) >= 4:
                            entity = parts[0].strip()
                            name = parts[1].strip()
                            username = parts[2].strip()
                            password = parts[3].strip()
                            permissions = [p.strip() for p in parts[4:]] if len(parts) > 4 else []
                            has_toggle = 'ok' in permissions
                            has_news = 'allow_add_gmail_of_news' in permissions
                            has_domain_checker = 'Domain_checker' in permissions
                            has_find_news = 'find_news' in permissions
                            has_extract_emails = 'Extract_emails' in permissions
                            has_tssw_report = 'tssw_report' in permissions
                            has_gmass = 'gmass' in permissions
                            has_blacklist_lookup = 'blacklist_lookup' in permissions
                            users.append({
                                'entity': entity,
                                'name': name,
                                'username': username,
                                'password': password,
                                'permissions': permissions,
                                'has_toggle_permission': has_toggle,
                                'has_news_permission': has_news,
                                'has_domain_checker_permission': has_domain_checker,
                                'has_find_news_permission': has_find_news,
                                'has_extract_emails_permission': has_extract_emails,
                                'has_tssw_report_permission': has_tssw_report,
                                'has_gmass_permission': has_gmass,
                                'has_blacklist_lookup_permission': has_blacklist_lookup
                            })
                        else:
                            logging.warning(f"Invalid format in users.txt line {line_num}: {line}")
                    except Exception as e:
                        logging.error(f"Error parsing users.txt line {line_num}: {e}")
    except FileNotFoundError:
        logging.error("users.txt file not found")
    except Exception as e:
        logging.error(f"Error reading users.txt: {e}")
    
    return users

def get_user_accounts(user_entity):
    """Get Gmail accounts accessible to a user based on their entity"""
    return gmail_manager.get_user_accounts(user_entity)

def authenticate_user(username, password):
    """Authenticate user against users.txt file and return user data dict"""
    users = load_users_from_file()
    for user_data in users:
        if user_data['username'] == username and user_data['password'] == password:
            return user_data
    return None

def connect_to_gmail(email_addr, password):
    """Connect to Gmail using IMAP with enhanced error handling and validation"""
    if not email_addr or not password:
        logging.error("Email address and password are required")
        return None
    
    # Basic email validation
    if '@' not in email_addr or '.' not in email_addr:
        logging.error(f"Invalid email address format: {email_addr}")
        return None
        
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(email_addr, password)
        logging.info(f"Successfully connected to Gmail account: {email_addr}")
        return mail
    except imaplib.IMAP4.error as e:
        logging.error(f"IMAP authentication failed for {email_addr}: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error connecting to Gmail {email_addr}: {e}")
        return None

def decode_mime_words(s):
    """Decode MIME encoded words"""
    if s is None:
        return ''
    
    decoded_parts = []
    for part, encoding in decode_header(s):
        if isinstance(part, bytes):
            if encoding:
                try:
                    decoded_parts.append(part.decode(encoding))
                except:
                    decoded_parts.append(part.decode('utf-8', errors='ignore'))
            else:
                decoded_parts.append(part.decode('utf-8', errors='ignore'))
        else:
            decoded_parts.append(str(part))
    
    return ''.join(decoded_parts)

def extract_and_analyze_emails(email_address, app_password, email_limit='all', folder_selection='all'):
    """Extract and analyze emails with SPF, DKIM, IP address, and categorization - Optimized for speed"""
    try:
        # Connect to Gmail
        mail = connect_to_gmail(email_address, app_password)
        if not mail:
            return None
        
        extracted_emails = []
        
        # Get folders to check based on user selection
        if folder_selection == 'inbox':
            folders_to_check = ['INBOX']
        elif folder_selection == 'spam':
            folders_to_check = ['[Gmail]/Spam']
        else:  # folder_selection == 'all'
            folders_to_check = ['INBOX', '[Gmail]/Spam']
        
        for folder in folders_to_check:
            try:
                mail.select(folder, readonly=True)  # Keep emails unread
                
                # Search for emails
                result, message_ids = mail.uid('search', 'ALL')
                if result != 'OK':
                    continue
                
                uid_list = message_ids[0].split()
                if not uid_list:
                    continue
                    
                # Apply email limit based on user selection
                if email_limit != 'all':
                    try:
                        limit = int(email_limit)  # No max limit restriction
                        uid_list = uid_list[-limit:] if len(uid_list) > limit else uid_list
                    except (ValueError, TypeError):
                        # Default to 50 if invalid limit
                        uid_list = uid_list[-50:] if len(uid_list) > 50 else uid_list
                
                # Pre-cache Gmail categories for inbox emails (only if needed)
                category_cache = {}
                if folder == 'INBOX':
                    category_cache = _build_category_cache_fast(mail, uid_list)
                
                # BATCH OPTIMIZATION: Fetch emails in batches instead of one by one
                # This reduces network round trips dramatically (500 requests → ~10 requests)
                batch_size = 50  # Process 50 emails at once
                total_emails = len(uid_list)
                
                for batch_start in range(0, total_emails, batch_size):
                    batch_end = min(batch_start + batch_size, total_emails)
                    batch_uids = uid_list[batch_start:batch_end]
                    
                    # Create UID range string for batch fetch
                    # Decode bytes to string for IMAP command
                    decoded_uids = [uid.decode() if isinstance(uid, bytes) else uid for uid in batch_uids]
                    uid_range = ','.join(decoded_uids)
                    
                    try:
                        # Fetch entire batch in ONE network request
                        result, msg_data = mail.uid('fetch', uid_range, '(BODY.PEEK[HEADER])')
                        if result != 'OK' or not msg_data:
                            continue
                        
                        # Process all emails in this batch
                        # msg_data is a list where each email is represented by a tuple (metadata, header_bytes)
                        # with occasional trailing non-tuple items we can ignore
                        for item in msg_data:
                            # Skip non-tuple items (like closing parenthesis bytes)
                            if not isinstance(item, tuple) or len(item) < 2:
                                continue
                                
                            try:
                                # Each tuple is (metadata_bytes, header_bytes)
                                metadata = item[0]
                                header_bytes = item[1]
                                
                                # Parse the UID from metadata
                                # metadata looks like: b'123 (UID 456 BODY[HEADER] {1234}'
                                uid_match = re.search(rb'UID (\d+)', metadata) if isinstance(metadata, bytes) else None
                                current_uid_bytes = uid_match.group(1) if uid_match else None
                                
                                # Skip if we can't parse UID or no header data
                                if not current_uid_bytes or not header_bytes:
                                    continue
                                
                                # Parse email headers
                                email_message = email.message_from_bytes(header_bytes)
                                
                                # Extract basic info
                                subject = decode_mime_words(email_message.get('Subject', ''))
                                from_header = email_message.get('From', '')
                                date_header = email_message.get('Date', '')
                                
                                # Parse from header
                                from_name, from_email = email.utils.parseaddr(from_header)
                                from_email = from_email.lower()
                                from_domain_extracted = from_email.split('@')[-1] if '@' in from_email else ''
                                
                                # Extract security info from headers efficiently
                                ip_address = extract_sender_ip_fast(email_message)
                                spf_status = extract_spf_status(email_message)
                                dkim_status = extract_dkim_status(email_message)
                                dmarc_status = extract_dmarc_status(email_message)
                                
                                # Determine email type and category
                                email_type = 'Spam' if folder == '[Gmail]/Spam' else 'Inbox'
                                # Keep UID as bytes to match category_cache keys
                                category = category_cache.get(current_uid_bytes, '') if folder == 'INBOX' else ''
                                
                                # Format date
                                try:
                                    parsed_date = email.utils.parsedate_to_datetime(date_header)
                                    formatted_date = parsed_date.strftime('%Y-%m-%d %H:%M')
                                except:
                                    formatted_date = date_header[:50] if date_header else 'Unknown'
                                
                                extracted_emails.append({
                                    'ip_address': ip_address,
                                    'spf_status': spf_status,
                                    'dkim_status': dkim_status,
                                    'dmarc_status': dmarc_status,
                                    'from_domain': from_domain_extracted,
                                    'subject': subject[:100],
                                    'email_type': email_type,
                                    'category': category,
                                    'date': formatted_date
                                })
                                
                            except Exception as e:
                                logging.error(f"Error processing email in batch: {e}")
                                continue
                                
                    except Exception as e:
                        logging.error(f"Error fetching batch: {e}")
                        continue
                        
            except Exception as e:
                logging.error(f"Error accessing folder {folder}: {e}")
                continue
        
        mail.logout()
        return extracted_emails
        
    except Exception as e:
        logging.error(f"Error in extract_and_analyze_emails: {e}")
        return None

def _build_category_cache_fast(mail, uid_list):
    """Build Gmail category cache using batch queries for speed"""
    category_cache = {}
    categories = ['social', 'promotions', 'updates', 'forums']
    
    for cat_key in categories:
        try:
            result, data = mail.uid('search', 'X-GM-RAW', f'"category:{cat_key}"')
            if result == 'OK' and data[0]:
                cat_uids = set(data[0].split())
                for uid in uid_list:
                    if uid in cat_uids:
                        category_cache[uid] = cat_key.capitalize()
        except Exception as e:
            logging.debug(f"Error caching category {cat_key}: {e}")
    
    return category_cache

def extract_sender_ip_fast(email_message):
    """Optimized IP extraction - faster version"""
    try:
        # Check Received headers (most common location)
        received_headers = email_message.get_all('Received', [])
        
        # Fast IP pattern matching
        ip_pattern = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
        
        for received in received_headers[:3]:  # Only check first 3 headers for speed
            matches = ip_pattern.findall(received)
            if matches:
                # Return the first external IP (not private)
                for ip in matches:
                    if not ip.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
                        return ip
                # If no external IP, return first IP
                return matches[0] if matches else None
        
        return None
    except:
        return None

def extract_sender_ip(email_message):
    """Extract sender IP address from email headers"""
    try:
        # Check various IP-containing headers
        received_headers = email_message.get_all('Received', [])
        
        for received in received_headers:
            # Look for IP addresses in Received headers

            ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
            matches = re.findall(ip_pattern, received)
            if matches:
                # Return the first external IP (not private)
                for ip in matches:
                    if not ip.startswith(('10.', '192.168.', '172.')):
                        return ip
                # If no external IP, return first IP
                return matches[0] if matches else None
        
        return None
    except:
        return None

def extract_spf_status(email_message):
    """Extract SPF status from Authentication-Results header"""
    try:
        auth_results = email_message.get('Authentication-Results', '')
        if 'spf=pass' in auth_results.lower():
            return 'PASS'
        elif 'spf=fail' in auth_results.lower():
            return 'FAIL'
        elif 'spf=softfail' in auth_results.lower():
            return 'SOFTFAIL'
        elif 'spf=neutral' in auth_results.lower():
            return 'NEUTRAL'
        elif 'spf=none' in auth_results.lower():
            return 'NONE'
        return 'UNKNOWN'
    except:
        return 'UNKNOWN'

def extract_dkim_status(email_message):
    """Extract DKIM status from Authentication-Results header"""
    try:
        auth_results = email_message.get('Authentication-Results', '')
        if 'dkim=pass' in auth_results.lower():
            return 'PASS'
        elif 'dkim=fail' in auth_results.lower():
            return 'FAIL'
        elif 'dkim=neutral' in auth_results.lower():
            return 'NEUTRAL'
        elif 'dkim=none' in auth_results.lower():
            return 'NONE'
        return 'UNKNOWN'
    except:
        return 'UNKNOWN'

def extract_dmarc_status(email_message):
    """Extract DMARC status from Authentication-Results header"""
    try:
        auth_results = email_message.get('Authentication-Results', '')
        if 'dmarc=pass' in auth_results.lower():
            return 'PASS'
        elif 'dmarc=fail' in auth_results.lower():
            return 'FAIL'
        elif 'dmarc=none' in auth_results.lower():
            return 'NONE'
        elif 'dmarc=quarantine' in auth_results.lower():
            return 'QUARANTINE'
        elif 'dmarc=reject' in auth_results.lower():
            return 'REJECT'
        return 'UNKNOWN'
    except:
        return 'UNKNOWN'

def get_gmail_category(mail, uid):
    """Get Gmail category for an email"""
    try:
        result, msg_data = mail.uid('fetch', uid, '(X-GM-LABELS)')
        if result == 'OK' and msg_data and msg_data[0]:
            labels_info = msg_data[0][1].decode('utf-8', errors='ignore') if isinstance(msg_data[0][1], bytes) else str(msg_data[0][1])
            
            if '\\\\Category\\\\Promotions' in labels_info or 'Category/Promotions' in labels_info:
                return 'Promotions'
            elif '\\\\Category\\\\Social' in labels_info or 'Category/Social' in labels_info:
                return 'Social'
            elif '\\\\Category\\\\Updates' in labels_info or 'Category/Updates' in labels_info:
                return 'Updates'
            elif '\\\\Category\\\\Forums' in labels_info or 'Category/Forums' in labels_info:
                return 'Forums'
            else:
                return 'Primary'
        return 'Primary'
    except:
        return 'Primary'

def get_improved_gmail_category(mail, uid):
    """Get Gmail category with improved detection using multiple methods"""
    try:
        # Method 1: Try X-GM-LABELS first (most reliable)
        result, msg_data = mail.uid('fetch', uid, '(X-GM-LABELS)')
        if result == 'OK' and msg_data and msg_data[0]:
            labels_info = msg_data[0][1].decode('utf-8', errors='ignore') if isinstance(msg_data[0][1], bytes) else str(msg_data[0][1])
            
            # Check for various label formats
            labels_lower = labels_info.lower()
            if any(keyword in labels_lower for keyword in ['category\\\\promotions', 'category/promotions', '"\\\\category\\\\promotions"']):
                return 'Promotions'
            elif any(keyword in labels_lower for keyword in ['category\\\\social', 'category/social', '"\\\\category\\\\social"']):
                return 'Social'
            elif any(keyword in labels_lower for keyword in ['category\\\\updates', 'category/updates', '"\\\\category\\\\updates"']):
                return 'Updates'
            elif any(keyword in labels_lower for keyword in ['category\\\\forums', 'category/forums', '"\\\\category\\\\forums"']):
                return 'Forums'
        
        # Method 2: Try Gmail search queries for categories
        try:
            # Check if email is in Promotions category using search
            status, data = mail.uid('search', 'X-GM-RAW', f'"category:promotions"')
            if status == 'OK' and data[0] and uid in data[0].split():
                return 'Promotions'
            
            # Check Social category
            status, data = mail.uid('search', 'X-GM-RAW', f'"category:social"')
            if status == 'OK' and data[0] and uid in data[0].split():
                return 'Social'
            
            # Check Updates category
            status, data = mail.uid('search', 'X-GM-RAW', f'"category:updates"')
            if status == 'OK' and data[0] and uid in data[0].split():
                return 'Updates'
            
            # Check Forums category
            status, data = mail.uid('search', 'X-GM-RAW', f'"category:forums"')
            if status == 'OK' and data[0] and uid in data[0].split():
                return 'Forums'
            
        except Exception as e:
            logging.debug(f"Gmail search method failed for UID {uid}: {e}")
        
        # Method 3: Fall back to header analysis for common patterns
        try:
            result, msg_data = mail.uid('fetch', uid, '(BODY.PEEK[HEADER])')
            if result == 'OK' and msg_data and msg_data[0]:
                header_content = msg_data[0][1].decode('utf-8', errors='ignore').lower()
                
                # Look for promotional indicators
                if any(keyword in header_content for keyword in ['unsubscribe', 'promotional', 'marketing', 'offer', 'deal']):
                    return 'Promotions'
                
                # Look for social indicators
                social_domains = ['facebook', 'twitter', 'linkedin', 'instagram', 'youtube', 'github']
                if any(domain in header_content for domain in social_domains):
                    return 'Social'
                
                # Look for update indicators
                if any(keyword in header_content for keyword in ['newsletter', 'update', 'notification', 'alert']):
                    return 'Updates'
                
        except Exception as e:
            logging.debug(f"Header analysis failed for UID {uid}: {e}")
        
        return 'Primary'
        
    except Exception as e:
        logging.debug(f"Improved category detection failed for UID {uid}: {e}")
        return 'Primary'

def get_gmail_folder_type(mail, uid):
    """Determine Gmail folder type based only on authentic Gmail X-GM-LABELS"""
    try:
        # Only use Gmail's authentic X-GM-LABELS - no content analysis fallback
        result, msg_data = mail.uid('fetch', uid, '(X-GM-LABELS)')
        if result == 'OK' and msg_data and msg_data[0]:
            try:
                labels_info = msg_data[0][1].decode('utf-8', errors='ignore') if isinstance(msg_data[0][1], bytes) else str(msg_data[0][1])
                logging.debug(f"Gmail labels for UID {uid}: {labels_info}")
                
                # Check for Gmail category labels - use exact Gmail format
                if '\\\\Category\\\\Promotions' in labels_info or 'Category/Promotions' in labels_info:
                    return 'Inbox/Promotions'
                elif '\\\\Category\\\\Social' in labels_info or 'Category/Social' in labels_info:
                    return 'Inbox/Social'
                elif '\\\\Category\\\\Updates' in labels_info or 'Category/Updates' in labels_info:
                    return 'Inbox/Updates'
                elif '\\\\Category\\\\Forums' in labels_info or 'Category/Forums' in labels_info:
                    return 'Inbox/Forums'
                    
            except Exception as e:
                logging.debug(f"Error parsing labels for UID {uid}: {e}")
            
    except Exception as e:
        logging.debug(f"Error fetching labels for UID {uid}: {e}")
    
    # Default to Primary if no Gmail category labels found
    return 'Inbox/Primary'





def format_time_ago(dt):
    """Convert datetime to 'X sec/min/hour/day' (without 'ago')"""
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    
    diff = now - dt
    seconds = int(diff.total_seconds())
    
    if seconds < 60:
        return f"{seconds} sec"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} min"
    elif seconds < 86400:
        hours = seconds // 3600
        return f"{hours} h"
    else:
        days = seconds // 86400
        return f"{days} day{'s' if days > 1 else ''}"









def get_emails_from_folder(mail, folder, folder_name, limit=20):
    """Get emails with accurate Gmail category detection — only for Inbox"""
    emails = []
    
    try:
        # Select the folder
        result = mail.select(folder)
        if result[0] != 'OK':
            return emails
        
        # Search for all UIDs
        result, data = mail.uid('SEARCH', None, 'ALL')
        if result != 'OK' or not data[0]:
            return emails
        
        email_uids = data[0].split()
        if not email_uids:
            return emails
        
        # Take only the most recent ones
        recent_uids = email_uids[-limit:]
        recent_uids.reverse()

        # === ONLY DETECT CATEGORIES IF THIS IS THE INBOX FOLDER ===
        use_category_detection = folder_name.lower() == 'inbox'

        # Cache for category UIDs (only if needed)
        cat_uid_sets = {}
        if use_category_detection:
            categories = {
                'social': 'Inbox/Social',
                'promotions': 'Inbox/Promotions',
                'updates': 'Inbox/Updates',
                'forums': 'Inbox/Forums',
                'purchases': 'Inbox/Purchases',
                'reservations': 'Inbox/Reservations'
            }

            for cat_key in categories:
                status, data = mail.uid('SEARCH', 'X-GM-RAW', f'"category:{cat_key}"')
                cat_uid_sets[cat_key] = set(data[0].split()) if status == 'OK' and data[0] else set()
        else:
            # For non-Inbox folders, we don't need categories
            pass

        # === FETCH EMAILS ===
        for uid in recent_uids:
            try:
                # Fetch only headers
                result, msg_data = mail.uid('fetch', uid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
                if result != 'OK' or not msg_data[0]:
                    continue

                msg = email.message_from_bytes(msg_data[0][1])

                from_header = msg.get('From', '')
                from_name, from_email = email.utils.parseaddr(from_header)
                from_name = decode_mime_words(from_name) if from_name else from_email

                subject = decode_mime_words(msg.get('Subject', 'No Subject'))

                date_header = msg.get('Date', '')
                try:
                    date_obj = email.utils.parsedate_to_datetime(date_header)
                    date_timestamp = date_obj.timestamp()
                    date_formatted = format_time_ago(date_obj)
                except:
                    date_timestamp = datetime.now().timestamp()
                    date_formatted = 'Unknown'

                # === DETERMINE FOLDER TYPE ===
                if use_category_detection:
                    # Only Inbox uses category tabs
                    detected_folder = 'Inbox/Primary'
                    for cat_key, folder_type_name in {
                        'social': 'Inbox/Social',
                        'promotions': 'Inbox/Promotions',
                        'updates': 'Inbox/Updates',
                        'forums': 'Inbox/Forums',
                        'purchases': 'Inbox/Purchases',
                        'reservations': 'Inbox/Reservations'
                    }.items():
                        if uid in cat_uid_sets[cat_key]:
                            detected_folder = folder_type_name
                            break
                else:
                    # Any other folder (Spam, Sent, etc.) → use folder name directly
                    detected_folder = folder_name  # e.g., "Spam", "Sent", etc.

                emails.append({
                    'folder': detected_folder,
                    'from_name': from_name,
                    'from_email': from_email,
                    'subject': subject,
                    'title': subject,
                    'date': date_timestamp,
                    'date_formatted': date_formatted
                })

            except Exception as e:
                logging.error(f"Error processing email UID {uid}: {e}")
                continue

    except Exception as e:
        logging.error(f"Error accessing folder {folder}: {e}")
    
    return emails

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please enter both username and password.', 'error')
            return render_template('login.html')
        
        # Authenticate user
        user_data = authenticate_user(username, password)
        if user_data:
            user_entity = user_data['entity']
            user_name = user_data['name']
            has_toggle = user_data['has_toggle_permission']
            has_news = user_data['has_news_permission']
            has_domain_checker = user_data['has_domain_checker_permission']
            has_find_news = user_data['has_find_news_permission']
            has_extract_emails = user_data['has_extract_emails_permission']
            
            user = User(username, user_entity, user_name, has_toggle, has_news, has_domain_checker, has_find_news, has_extract_emails)
            login_user(user, remember=True)
            
            flash(f'Welcome, {user_name}!', 'success')
            
            # Redirect to next page if requested, otherwise services
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            return redirect(url_for('services'))
        else:
            flash('Invalid username or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    flash(f'You have been logged out successfully, {username}.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return redirect(url_for('services'))

@app.route('/services')
@login_required
def services():
    """Main services selection page"""
    return render_template('services.html', current_user=current_user)

@app.route('/extract_emails', methods=['GET', 'POST'])
@login_required
def extract_emails():
    """TSS Extract Emails service"""
    if not current_user.has_extract_emails_permission:
        flash('You do not have permission to access the Extract Emails service.', 'error')
        return redirect(url_for('services'))
    
    if request.method == 'GET':
        return render_template('extract_emails.html', current_user=current_user)
    
    # Handle POST request for email extraction
    try:
        email_address = request.form.get('email_address', '').strip()
        app_password = request.form.get('app_password', '').strip()
        
        # Validate required fields
        if not email_address or not app_password:
            return jsonify({'success': False, 'error': 'Email address and app password are required'})
        
        # Get email limit from form
        email_limit = request.form.get('email_limit', 'all').strip()
        if email_limit == 'limited':
            custom_limit = request.form.get('custom_limit', '50').strip()
            email_limit = custom_limit
        
        # Get folder selection
        folder_selection = request.form.get('folder_selection', 'all')
        
        # Extract and analyze emails
        extracted_data = extract_and_analyze_emails(email_address, app_password, email_limit, folder_selection)
        
        if extracted_data is None:
            return jsonify({'success': False, 'error': 'Failed to connect to Gmail account. Please check your credentials.'})
        
        return jsonify({'success': True, 'data': extracted_data})
        
    except Exception as e:
        logging.error(f"Error in extract_emails: {e}")
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'})

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    selected_account = ''
    emails = []
    error = ''
    email_limit = 50
    search_sender = ''
    search_subject = ''
    
    # Get accounts available to current user
    user_accounts = get_user_accounts(current_user.entity)
    
    if request.method == 'POST':
        # Input validation and sanitization
        selected_account = request.form.get('account', '').strip()
        try:
            email_limit = int(request.form.get('email_limit', 50))
            # Limit email_limit to reasonable bounds
            email_limit = max(1, min(email_limit, 50))
        except (ValueError, TypeError):
            email_limit = 50
            
        search_sender = request.form.get('search_sender', '').strip()[:100]  # Limit length
        search_subject = request.form.get('search_subject', '').strip()[:200]  # Limit length
        
        if selected_account and selected_account in user_accounts:
            account_data = user_accounts[selected_account]
            
            # Handle TSSW account selection
            if current_user.entity == 'TSSW':
                gmail_manager.connect_tssw_account(current_user.username, selected_account)
            
            # Get emails from connection manager
            emails = gmail_manager.get_emails(selected_account)
            
            if not emails:
                error = f'Loading emails for {account_data["email"]}... This may take a moment.'
    
    # Get account status information for toggle buttons
    accounts_with_status = {}
    if current_user.entity == 'TSSW' or current_user.has_toggle_permission:
        accounts_status = gmail_manager.get_all_accounts_status(current_user.entity)
        for account_key, account_info in user_accounts.items():
            status_info = accounts_status.get(account_key, {})
            accounts_with_status[account_key] = {
                **account_info,
                'connection_status': status_info.get('status', 'disconnected'),
                'email_count': status_info.get('email_count', 0)
            }
    else:
        # Regular users without toggle permissions - just basic account info
        accounts_with_status = user_accounts
    
    return render_template('dashboard.html', 
                         accounts=accounts_with_status,
                         selected_account=selected_account,
                         emails=emails,
                         error=error,
                         email_limit=email_limit,
                         search_sender=search_sender,
                         search_subject=search_subject,
                         current_user=current_user,
                         show_toggles=(current_user.entity == 'TSSW' or current_user.has_toggle_permission))

@app.route('/fetch_emails', methods=['POST'])
@login_required
def fetch_emails():
    """API endpoint to fetch emails using connection manager"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided', 'emails': []})
            
        # Get accounts available to current user
        user_accounts = get_user_accounts(current_user.entity)
            
        # Input validation and sanitization
        selected_account = str(data.get('account', '')).strip()
        try:
            email_limit = int(data.get('email_limit', 50))
            # Enforce reasonable bounds
            email_limit = max(1, min(email_limit, 50))
        except (ValueError, TypeError):
            email_limit = 50
            
        search_sender = str(data.get('search_sender', ''))[:100]  # Limit length
        search_subject = str(data.get('search_subject', ''))[:200]  # Limit length
        
        if not selected_account or selected_account not in user_accounts:
            return jsonify({'error': 'Invalid account selected', 'emails': []})
        
        account_data = user_accounts[selected_account]
        
        # Handle TSSW account selection
        if current_user.entity == 'TSSW':
            gmail_manager.connect_tssw_account(current_user.username, selected_account)
        
        # Get emails from connection manager
        emails = gmail_manager.get_emails(selected_account)
        
        return jsonify({
            'error': '',
            'emails': emails,
            'email_count': len(emails),
            'email_limit': email_limit,
            'search_sender': search_sender,
            'search_subject': search_subject
        })
            
    except Exception as e:
        logging.error(f"Error in fetch_emails endpoint: {e}")
        return jsonify({'error': f'Server error: {str(e)}', 'emails': []})

@app.route('/events/<account_key>')
@login_required
def events(account_key):
    """Server-Sent Events endpoint for real-time email updates"""
    # Verify user has access to this account
    user_accounts = get_user_accounts(current_user.entity)
    if account_key not in user_accounts:
        return Response("Unauthorized", status=403)
    
    # Handle TSSW account selection for events
    if current_user.entity == 'TSSW':
        gmail_manager.connect_tssw_account(current_user.username, account_key)
    
    def event_stream():
        try:
            # Queue to receive updates
            import queue
            update_queue = queue.Queue(maxsize=10)  # Limit queue size
            
            def callback(acc_key, emails):
                if acc_key == account_key:
                    try:
                        update_queue.put_nowait(emails)
                    except queue.Full:
                        # Remove old items if queue is full
                        try:
                            update_queue.get_nowait()
                            update_queue.put_nowait(emails)
                        except:
                            pass
            
            # Add callback to connection manager
            gmail_manager.add_update_callback(account_key, callback)
            
            # Send initial data
            emails = gmail_manager.get_emails(account_key)
            yield f"data: {json.dumps({'emails': emails if emails else []})}\n\n"
            
            # Listen for updates with timeout limit
            heartbeat_count = 0
            max_heartbeats = 20  # Max 10 minutes of heartbeats
            
            while heartbeat_count < max_heartbeats:
                try:
                    emails = update_queue.get(timeout=15)  # Reduced timeout
                    yield f"data: {json.dumps({'emails': emails if emails else []})}\n\n"
                    heartbeat_count = 0  # Reset heartbeat count on successful update
                except queue.Empty:
                    # Send heartbeat
                    heartbeat_count += 1
                    yield f"data: {json.dumps({'heartbeat': True, 'count': heartbeat_count})}\n\n"
                    
        except Exception as e:
            logging.error(f"Error in event stream for {account_key}: {e}")
            yield f"data: {json.dumps({'error': str(e), 'account': account_key})}\n\n"
    
    return Response(event_stream(), mimetype='text/event-stream')

@app.route('/api/toggle_account', methods=['POST'])
@login_required
def toggle_account():
    """API endpoint to toggle Gmail account connection"""
    try:
        data = request.get_json()
        account_key = data.get('account_key')
        force_state = data.get('force_state')  # 'on' or 'off' or None for toggle
        
        if not account_key:
            return jsonify({'success': False, 'error': 'Account key required'}), 400
        
        # Check permissions
        if current_user.entity != 'TSSW' and not current_user.has_toggle_permission:
            return jsonify({'success': False, 'error': 'Permission denied'}), 403
        
        # Verify user has access to this account
        user_accounts = get_user_accounts(current_user.entity)
        if account_key not in user_accounts:
            return jsonify({'success': False, 'error': 'Account not found'}), 404
        
        # Toggle the account
        success = gmail_manager.toggle_account_connection(
            current_user.username,
            current_user.entity, 
            account_key,
            force_state
        )
        
        if success:
            # Get updated status
            new_status = gmail_manager.get_account_connection_status(account_key)
            return jsonify({
                'success': True,
                'new_status': new_status,
                'account_key': account_key
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to toggle account'}), 500
            
    except Exception as e:
        logging.error(f"Error toggling account: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/account_status/<account_key>')
@login_required  
def get_account_status(account_key):
    """API endpoint to get account connection status"""
    try:
        # Check permissions
        if current_user.entity != 'TSSW' and not current_user.has_toggle_permission:
            return jsonify({'error': 'Permission denied'}), 403
        
        # Verify user has access to this account
        user_accounts = get_user_accounts(current_user.entity)
        if account_key not in user_accounts:
            return jsonify({'error': 'Account not found'}), 404
        
        status = gmail_manager.get_account_connection_status(account_key)
        email_count = len(gmail_manager.get_emails(account_key))
        
        return jsonify({
            'account_key': account_key,
            'status': status,
            'email_count': email_count
        })
        
    except Exception as e:
        logging.error(f"Error getting account status: {e}")
        return jsonify({'error': str(e)}), 500

# Removed - entity-based connections don't need individual unsubscribe

@app.route('/find_news')
@login_required
def find_news():
    """Find News dashboard - displays news Gmail accounts"""
    if not current_user.has_find_news_permission:
        flash('You do not have permission to access the Find News service.', 'error')
        return redirect(url_for('services'))
    
    news_accounts = gmail_manager.get_news_accounts(current_user.entity)
    
    # Get list of entities for TSSW users (they can add accounts to any entity)
    entities = []
    if current_user.entity.upper() == 'TSSW':
        entities = ['TSS1', 'TSS2', 'TSS3', 'TSSF', 'TSSW']
    
    return render_template('find_news.html', 
                         accounts=news_accounts,
                         selected_account=None,
                         can_manage_news=current_user.has_news_permission,
                         entities=entities,
                         user_entity=current_user.entity.upper())

def load_news_accounts_for_management(user_entity):
    """Load news accounts that a user can manage (from their entity or all if TSSW)"""
    accounts = []
    try:
        with open('gmailaccounts.txt', 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(',')
                    if len(parts) >= 4 and parts[3].strip().lower() == 'news':
                        entity = parts[0].strip().upper()
                        email_addr = parts[1].strip()
                        app_password = parts[2].strip()
                        
                        # TSSW can see all, others only their entity
                        if user_entity.upper() == 'TSSW' or entity == user_entity.upper():
                            accounts.append({
                                'entity': entity,
                                'email': email_addr,
                                'app_password': app_password,
                                'line_num': line_num
                            })
    except FileNotFoundError:
        logging.error("gmailaccounts.txt file not found")
    except Exception as e:
        logging.error(f"Error reading gmailaccounts.txt: {e}")
    return accounts

def save_news_account(entity, email, app_password):
    """Add a new news Gmail account to gmailaccounts.txt"""
    try:
        with open('gmailaccounts.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{entity},{email},{app_password},news")
        gmail_manager.load_gmail_accounts()
        return True
    except Exception as e:
        logging.error(f"Error saving news account: {e}")
        return False

def update_news_account(old_entity, old_email, new_entity, new_email, new_password):
    """Update an existing news Gmail account in gmailaccounts.txt"""
    try:
        lines = []
        found = False
        with open('gmailaccounts.txt', 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    parts = stripped.split(',')
                    if len(parts) >= 4 and parts[3].strip().lower() == 'news':
                        if parts[0].strip().upper() == old_entity.upper() and parts[1].strip() == old_email:
                            lines.append(f"{new_entity},{new_email},{new_password},news\n")
                            found = True
                            continue
                lines.append(line if line.endswith('\n') else line + '\n')
        
        if found:
            with open('gmailaccounts.txt', 'w', encoding='utf-8') as f:
                f.writelines(lines)
            gmail_manager.load_gmail_accounts()
        return found
    except Exception as e:
        logging.error(f"Error updating news account: {e}")
        return False

def delete_news_account(entity, email):
    """Delete a news Gmail account from gmailaccounts.txt"""
    try:
        lines = []
        found = False
        with open('gmailaccounts.txt', 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    parts = stripped.split(',')
                    if len(parts) >= 4 and parts[3].strip().lower() == 'news':
                        if parts[0].strip().upper() == entity.upper() and parts[1].strip() == email:
                            found = True
                            continue
                lines.append(line if line.endswith('\n') else line + '\n')
        
        if found:
            with open('gmailaccounts.txt', 'w', encoding='utf-8') as f:
                f.writelines(lines)
            gmail_manager.load_gmail_accounts()
        return found
    except Exception as e:
        logging.error(f"Error deleting news account: {e}")
        return False

def load_extraction_accounts():
    """Load Gmail accounts with allow_extraction flag for TSSW users (legacy - only for y.ouiguemane)"""
    accounts = []
    try:
        with open('gmailaccounts.txt', 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(',')
                    if len(parts) >= 4 and parts[3].strip().lower() == 'allow_extraction':
                        entity = parts[0].strip().upper()
                        email_addr = parts[1].strip()
                        app_password = parts[2].strip()
                        accounts.append({
                            'entity': entity,
                            'email': email_addr,
                            'app_password': app_password,
                            'line_num': line_num,
                            'is_legacy': True
                        })
    except FileNotFoundError:
        logging.error("gmailaccounts.txt file not found")
    except Exception as e:
        logging.error(f"Error reading gmailaccounts.txt: {e}")
    return accounts

def load_user_extraction_accounts(username):
    """Load extraction accounts for a specific user from user_extraction_accounts.txt"""
    accounts = []
    try:
        with open('user_extraction_accounts.txt', 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(',')
                    if len(parts) >= 3:
                        account_username = parts[0].strip()
                        if account_username == username:
                            email_addr = parts[1].strip()
                            app_password = parts[2].strip()
                            accounts.append({
                                'username': account_username,
                                'email': email_addr,
                                'app_password': app_password,
                                'line_num': line_num,
                                'is_legacy': False
                            })
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.error(f"Error reading user_extraction_accounts.txt: {e}")
    return accounts

def save_user_extraction_account(username, email, app_password):
    """Add a new extraction Gmail account for a user to user_extraction_accounts.txt"""
    try:
        with open('user_extraction_accounts.txt', 'a', encoding='utf-8') as f:
            f.write(f"\n{username},{email},{app_password}")
        return True
    except Exception as e:
        logging.error(f"Error saving user extraction account: {e}")
        return False

def update_user_extraction_account(username, old_email, new_email, new_password):
    """Update an existing user extraction Gmail account in user_extraction_accounts.txt"""
    try:
        lines = []
        found = False
        with open('user_extraction_accounts.txt', 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    parts = stripped.split(',')
                    if len(parts) >= 3:
                        account_username = parts[0].strip()
                        account_email = parts[1].strip()
                        if account_username == username and account_email == old_email:
                            lines.append(f"{username},{new_email},{new_password}\n")
                            found = True
                            continue
                lines.append(line if line.endswith('\n') else line + '\n')
        
        if found:
            with open('user_extraction_accounts.txt', 'w', encoding='utf-8') as f:
                f.writelines(lines)
        return found
    except Exception as e:
        logging.error(f"Error updating user extraction account: {e}")
        return False

def delete_user_extraction_account(username, email):
    """Delete a user extraction Gmail account from user_extraction_accounts.txt"""
    try:
        lines = []
        found = False
        with open('user_extraction_accounts.txt', 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    parts = stripped.split(',')
                    if len(parts) >= 3:
                        account_username = parts[0].strip()
                        account_email = parts[1].strip()
                        if account_username == username and account_email == email:
                            found = True
                            continue
                lines.append(line if line.endswith('\n') else line + '\n')
        
        if found:
            with open('user_extraction_accounts.txt', 'w', encoding='utf-8') as f:
                f.writelines(lines)
        return found
    except Exception as e:
        logging.error(f"Error deleting user extraction account: {e}")
        return False

def save_extraction_account(email, app_password):
    """Add a new extraction Gmail account to gmailaccounts.txt (legacy)"""
    try:
        with open('gmailaccounts.txt', 'a', encoding='utf-8') as f:
            f.write(f"\nEXTRACTION,{email},{app_password},allow_extraction")
        gmail_manager.load_gmail_accounts()
        return True
    except Exception as e:
        logging.error(f"Error saving extraction account: {e}")
        return False

def update_extraction_account(old_email, new_email, new_password):
    """Update an existing extraction Gmail account in gmailaccounts.txt (legacy)"""
    try:
        lines = []
        found = False
        with open('gmailaccounts.txt', 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    parts = stripped.split(',')
                    if len(parts) >= 4 and parts[3].strip().lower() == 'allow_extraction':
                        if parts[1].strip() == old_email:
                            entity = parts[0].strip()
                            lines.append(f"{entity},{new_email},{new_password},allow_extraction\n")
                            found = True
                            continue
                lines.append(line if line.endswith('\n') else line + '\n')
        
        if found:
            with open('gmailaccounts.txt', 'w', encoding='utf-8') as f:
                f.writelines(lines)
            gmail_manager.load_gmail_accounts()
        return found
    except Exception as e:
        logging.error(f"Error updating extraction account: {e}")
        return False

def delete_extraction_account(email):
    """Delete an extraction Gmail account from gmailaccounts.txt (legacy)"""
    try:
        lines = []
        found = False
        with open('gmailaccounts.txt', 'r', encoding='utf-8') as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    parts = stripped.split(',')
                    if len(parts) >= 4 and parts[3].strip().lower() == 'allow_extraction':
                        if parts[1].strip() == email:
                            found = True
                            continue
                lines.append(line if line.endswith('\n') else line + '\n')
        
        if found:
            with open('gmailaccounts.txt', 'w', encoding='utf-8') as f:
                f.writelines(lines)
            gmail_manager.load_gmail_accounts()
        return found
    except Exception as e:
        logging.error(f"Error deleting extraction account: {e}")
        return False

@app.route('/api/extraction_accounts', methods=['GET'])
@login_required
def get_extraction_accounts():
    """Get extraction accounts for the current user"""
    if not current_user.has_extract_emails_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    # Get user-specific accounts
    user_accounts = load_user_extraction_accounts(current_user.username)
    
    # For y.ouiguemane, also include legacy TSSW accounts
    if current_user.username == 'y.ouiguemane':
        legacy_accounts = load_extraction_accounts()
        user_accounts = user_accounts + legacy_accounts
    
    return jsonify({'success': True, 'accounts': user_accounts})

@app.route('/api/extraction_accounts', methods=['POST'])
@login_required
def add_extraction_account():
    """Add a new extraction Gmail account for the current user"""
    if not current_user.has_extract_emails_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    email = data.get('email', '').strip()
    app_password = data.get('app_password', '').strip()
    
    if not email or not app_password:
        return jsonify({'error': 'Email and app password are required'}), 400
    
    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Invalid email format'}), 400
    
    if save_user_extraction_account(current_user.username, email, app_password):
        return jsonify({'success': True, 'message': 'Account added successfully'})
    else:
        return jsonify({'error': 'Failed to add account'}), 500

@app.route('/api/extraction_accounts', methods=['PUT'])
@login_required
def update_extraction_account_route():
    """Update an existing extraction Gmail account"""
    if not current_user.has_extract_emails_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    old_email = data.get('old_email', '').strip()
    new_email = data.get('email', '').strip()
    new_password = data.get('app_password', '').strip()
    is_legacy = data.get('is_legacy', False)
    
    if not all([old_email, new_email, new_password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    # Handle legacy accounts (only for y.ouiguemane)
    if is_legacy:
        if current_user.username != 'y.ouiguemane':
            return jsonify({'error': 'Permission denied for legacy accounts'}), 403
        if update_extraction_account(old_email, new_email, new_password):
            return jsonify({'success': True, 'message': 'Account updated successfully'})
        else:
            return jsonify({'error': 'Account not found or update failed'}), 404
    
    # Handle user-specific accounts
    if update_user_extraction_account(current_user.username, old_email, new_email, new_password):
        return jsonify({'success': True, 'message': 'Account updated successfully'})
    else:
        return jsonify({'error': 'Account not found or update failed'}), 404

@app.route('/api/extraction_accounts', methods=['DELETE'])
@login_required
def delete_extraction_account_route():
    """Delete an extraction Gmail account"""
    if not current_user.has_extract_emails_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    email = data.get('email', '').strip()
    is_legacy = data.get('is_legacy', False)
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    # Handle legacy accounts (only for y.ouiguemane)
    if is_legacy:
        if current_user.username != 'y.ouiguemane':
            return jsonify({'error': 'Permission denied for legacy accounts'}), 403
        if delete_extraction_account(email):
            return jsonify({'success': True, 'message': 'Account deleted successfully'})
        else:
            return jsonify({'error': 'Account not found or delete failed'}), 404
    
    # Handle user-specific accounts
    if delete_user_extraction_account(current_user.username, email):
        return jsonify({'success': True, 'message': 'Account deleted successfully'})
    else:
        return jsonify({'error': 'Account not found or delete failed'}), 404

@app.route('/api/news_accounts', methods=['GET'])
@login_required
def get_manageable_news_accounts():
    """Get news accounts that the current user can manage"""
    if not current_user.has_news_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    accounts = load_news_accounts_for_management(current_user.entity)
    return jsonify({'success': True, 'accounts': accounts})

@app.route('/api/news_accounts', methods=['POST'])
@login_required
def add_news_account():
    """Add a new news Gmail account"""
    if not current_user.has_news_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    entity = data.get('entity', '').strip().upper()
    email = data.get('email', '').strip()
    app_password = data.get('app_password', '').strip()
    
    if not entity or not email or not app_password:
        return jsonify({'error': 'All fields are required'}), 400
    
    # Non-TSSW users can only add to their own entity
    if current_user.entity.upper() != 'TSSW' and entity != current_user.entity.upper():
        return jsonify({'error': 'You can only add accounts to your own entity'}), 403
    
    # Validate email format
    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Invalid email format'}), 400
    
    if save_news_account(entity, email, app_password):
        return jsonify({'success': True, 'message': 'Account added successfully'})
    else:
        return jsonify({'error': 'Failed to add account'}), 500

@app.route('/api/news_accounts', methods=['PUT'])
@login_required
def update_news_account_route():
    """Update an existing news Gmail account"""
    if not current_user.has_news_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    old_entity = data.get('old_entity', '').strip().upper()
    old_email = data.get('old_email', '').strip()
    new_entity = data.get('entity', '').strip().upper()
    new_email = data.get('email', '').strip()
    new_password = data.get('app_password', '').strip()
    
    if not all([old_entity, old_email, new_entity, new_email, new_password]):
        return jsonify({'error': 'All fields are required'}), 400
    
    # Check permissions
    if current_user.entity.upper() != 'TSSW':
        if old_entity != current_user.entity.upper() or new_entity != current_user.entity.upper():
            return jsonify({'error': 'You can only modify accounts in your own entity'}), 403
    
    if update_news_account(old_entity, old_email, new_entity, new_email, new_password):
        return jsonify({'success': True, 'message': 'Account updated successfully'})
    else:
        return jsonify({'error': 'Account not found or update failed'}), 404

@app.route('/api/news_accounts', methods=['DELETE'])
@login_required
def delete_news_account_route():
    """Delete a news Gmail account"""
    if not current_user.has_news_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    entity = data.get('entity', '').strip().upper()
    email = data.get('email', '').strip()
    
    if not entity or not email:
        return jsonify({'error': 'Entity and email are required'}), 400
    
    # Check permissions
    if current_user.entity.upper() != 'TSSW' and entity != current_user.entity.upper():
        return jsonify({'error': 'You can only delete accounts from your own entity'}), 403
    
    if delete_news_account(entity, email):
        return jsonify({'success': True, 'message': 'Account deleted successfully'})
    else:
        return jsonify({'error': 'Account not found or delete failed'}), 404

@app.route('/api/news_emails/<account_key>')
@login_required
def get_news_emails(account_key):
    """Fetch last 50 inbox emails for a news account"""
    try:
        news_accounts = gmail_manager.get_news_accounts(current_user.entity)
        if account_key not in news_accounts:
            return jsonify({'error': 'Account not found or unauthorized'}), 404
        
        account = news_accounts[account_key]
        emails = fetch_news_emails_fast(account['email'], account['app_password'], limit=50)
        
        return jsonify({
            'success': True,
            'emails': emails,
            'account_key': account_key
        })
    except Exception as e:
        logging.error(f"Error fetching news emails: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/email_source/<account_key>/<uid>')
@login_required
def get_email_source(account_key, uid):
    """Get full email source (headers, MIME parts) for copying"""
    try:
        news_accounts = gmail_manager.get_news_accounts(current_user.entity)
        if account_key not in news_accounts:
            return jsonify({'error': 'Account not found or unauthorized'}), 404
        
        account = news_accounts[account_key]
        source = fetch_email_source(account['email'], account['app_password'], uid)
        
        if source:
            return jsonify({
                'success': True,
                'source': source,
                'uid': uid
            })
        else:
            return jsonify({'error': 'Email not found'}), 404
    except Exception as e:
        logging.error(f"Error fetching email source: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/news_events/<account_key>')
@login_required
def news_events(account_key):
    """Server-Sent Events for real-time news email updates"""
    news_accounts = gmail_manager.get_news_accounts(current_user.entity)
    if account_key not in news_accounts:
        return Response("Unauthorized", status=403)
    
    account = news_accounts[account_key]
    
    def event_stream():
        try:
            last_check_time = 0
            check_interval = 10  # Check every 10 seconds for new emails
            
            while True:
                current_time = time.time()
                
                if current_time - last_check_time >= check_interval:
                    try:
                        emails = fetch_news_emails_fast(account['email'], account['app_password'], limit=50)
                        yield f"data: {json.dumps({'emails': emails, 'timestamp': current_time})}\n\n"
                        last_check_time = current_time
                    except Exception as e:
                        logging.error(f"Error fetching news emails in SSE: {e}")
                        yield f"data: {json.dumps({'error': str(e)})}\n\n"
                else:
                    # Send heartbeat
                    yield f"data: {json.dumps({'heartbeat': True})}\n\n"
                
                time.sleep(5)  # Sleep 5 seconds between checks
                
        except Exception as e:
            logging.error(f"Error in news event stream: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return Response(event_stream(), mimetype='text/event-stream')

def fetch_news_emails_fast(email_addr, app_password, limit=50):
    """Fetch last N inbox emails quickly (excluding spam) with Gmail folder/category info"""
    emails = []
    mail = None
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(email_addr, app_password)
        mail.select('INBOX')
        
        result, data = mail.uid('SEARCH', None, 'ALL')
        if result != 'OK' or not data[0]:
            return emails
        
        email_uids = data[0].split()
        if not email_uids:
            return emails
        
        recent_uids = email_uids[-limit:]
        recent_uids.reverse()
        
        category_cache = {}
        categories = ['social', 'promotions', 'updates', 'forums']
        for cat_key in categories:
            try:
                result_cat, data_cat = mail.uid('search', 'X-GM-RAW', f'"category:{cat_key}"')
                if result_cat == 'OK' and data_cat[0]:
                    cat_uids = set(data_cat[0].split())
                    for uid in recent_uids:
                        if uid in cat_uids:
                            category_cache[uid] = cat_key.capitalize()
            except Exception as e:
                logging.debug(f"Error caching category {cat_key}: {e}")
        
        for uid in recent_uids:
            try:
                uid_str = uid.decode() if isinstance(uid, bytes) else str(uid)
                result, msg_data = mail.uid('fetch', uid, '(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])')
                if result != 'OK' or not msg_data[0]:
                    continue
                
                msg = email.message_from_bytes(msg_data[0][1])
                
                from_header = msg.get('From', '')
                from_name, from_email_addr = email.utils.parseaddr(from_header)
                from_name = decode_mime_words(from_name) if from_name else from_email_addr
                
                from_domain = ''
                if '@' in from_email_addr:
                    from_domain = from_email_addr.split('@')[1]
                
                subject = decode_mime_words(msg.get('Subject', 'No Subject'))
                
                date_header = msg.get('Date', '')
                try:
                    date_obj = email.utils.parsedate_to_datetime(date_header)
                    date_str = date_obj.strftime('%Y-%m-%d %H:%M')
                except:
                    date_str = date_header[:20] if date_header else 'Unknown'
                
                folder = category_cache.get(uid, 'Primary')
                
                emails.append({
                    'uid': uid_str,
                    'subject': subject[:100] if len(subject) > 100 else subject,
                    'from_name': from_name[:50] if len(from_name) > 50 else from_name,
                    'from_domain': from_domain,
                    'date': date_str,
                    'folder': folder
                })
                
            except Exception as e:
                logging.debug(f"Error processing email UID {uid}: {e}")
                continue
                
    except Exception as e:
        logging.error(f"Error in fetch_news_emails_fast: {e}")
    finally:
        if mail:
            try:
                mail.logout()
            except:
                pass
    
    return emails

def fetch_email_source(email_addr, app_password, uid):
    """Fetch full email source (headers + body + MIME parts)"""
    mail = None
    try:
        mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        mail.login(email_addr, app_password)
        mail.select('INBOX')
        
        result, msg_data = mail.uid('fetch', uid, '(RFC822)')
        if result != 'OK' or not msg_data[0]:
            return None
        
        raw_email = msg_data[0][1]
        if isinstance(raw_email, bytes):
            return raw_email.decode('utf-8', errors='replace')
        return str(raw_email)
        
    except Exception as e:
        logging.error(f"Error fetching email source: {e}")
        return None
    finally:
        if mail:
            try:
                mail.logout()
            except:
                pass

def get_dns_resolver():
    """Get a configured DNS resolver with timeout and reliable nameservers"""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
    return resolver

def lookup_dmarc(domain):
    """Lookup DMARC record for a domain"""
    try:
        resolver = get_dns_resolver()
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_parts = []
            for s in rdata.strings:
                if isinstance(s, bytes):
                    txt_parts.append(s.decode('utf-8', errors='replace'))
                else:
                    txt_parts.append(str(s))
            txt_value = ''.join(txt_parts)
            if txt_value.lower().startswith('v=dmarc1'):
                return txt_value
        return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
        return None
    except Exception as e:
        logging.debug(f"DMARC lookup error for {domain}: {e}")
        return None

def lookup_mx(domain):
    """Lookup MX records for a domain"""
    try:
        resolver = get_dns_resolver()
        answers = resolver.resolve(domain, 'MX')
        mx_records = []
        for rdata in answers:
            mx_records.append(f"{rdata.preference} {rdata.exchange}")
        return mx_records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
        return None
    except Exception as e:
        logging.debug(f"MX lookup error for {domain}: {e}")
        return None

def lookup_txt(domain):
    """Lookup TXT records for a domain"""
    try:
        resolver = get_dns_resolver()
        answers = resolver.resolve(domain, 'TXT')
        txt_records = []
        for rdata in answers:
            txt_parts = []
            for s in rdata.strings:
                if isinstance(s, bytes):
                    txt_parts.append(s.decode('utf-8', errors='replace'))
                else:
                    txt_parts.append(str(s))
            txt_records.append(''.join(txt_parts))
        return txt_records
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
        return None
    except Exception as e:
        logging.debug(f"TXT lookup error for {domain}: {e}")
        return None

def is_valid_ip(ip):
    """Check if a string is a valid IPv4 address"""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

@app.route('/domain_checker')
@login_required
def domain_checker():
    """Domain checker service - DNS lookup tools"""
    if not current_user.has_domain_checker_permission:
        flash('You do not have permission to access the Domain Checker service.', 'error')
        return redirect(url_for('services'))
    return render_template('domain_checker.html')

@app.route('/api/domain_checker/dmarc', methods=['POST'])
@login_required
def api_dmarc_lookup():
    """API endpoint for DMARC lookups with parallel processing"""
    if not current_user.has_domain_checker_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    domains_text = data.get('domains', '')
    
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    
    results = [None] * len(domains)
    max_workers = min(20, len(domains)) if domains else 1
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_index = {executor.submit(lookup_dmarc, domain): (i, domain) for i, domain in enumerate(domains)}
        for future in as_completed(future_to_index):
            idx, domain = future_to_index[future]
            try:
                dmarc_record = future.result()
                results[idx] = {
                    'domain': domain,
                    'dmarc': dmarc_record if dmarc_record else 'Not Found'
                }
            except Exception:
                results[idx] = {
                    'domain': domain,
                    'dmarc': 'Not Found'
                }
    
    return jsonify({'results': results})

@app.route('/api/domain_checker/dmarc_stream', methods=['GET'])
@login_required
def api_dmarc_lookup_stream():
    """SSE endpoint for DMARC lookups with real-time progress"""
    if not current_user.has_domain_checker_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    domains_text = request.args.get('domains', '')
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    
    def generate():
        total = len(domains)
        if total == 0:
            yield f"data: {json.dumps({'type': 'complete', 'results': []})}\n\n"
            return
        
        results = [None] * total
        completed = 0
        max_workers = min(20, total)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {executor.submit(lookup_dmarc, domain): (i, domain) for i, domain in enumerate(domains)}
            
            for future in as_completed(future_to_index):
                idx, domain = future_to_index[future]
                try:
                    dmarc_record = future.result()
                    results[idx] = {
                        'domain': domain,
                        'dmarc': dmarc_record if dmarc_record else 'Not Found'
                    }
                except Exception:
                    results[idx] = {
                        'domain': domain,
                        'dmarc': 'Not Found'
                    }
                
                completed += 1
                
                progress_data = {
                    'type': 'progress',
                    'current': completed,
                    'total': total,
                    'domain': domain
                }
                yield f"data: {json.dumps(progress_data)}\n\n"
        
        complete_data = {
            'type': 'complete',
            'results': results
        }
        yield f"data: {json.dumps(complete_data)}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/api/domain_checker/dmarc_download', methods=['POST'])
@login_required
def api_dmarc_download():
    """Generate download file for domains missing DMARC records"""
    if not current_user.has_domain_checker_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    domains_text = data.get('domains', '')
    template = data.get('template', 'v=DMARC1; p=reject; rua=mailto:postmaster@[domain]; ruf=mailto:dmarc@[domain]; fo=1; pct=100')
    
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    
    lines = []
    for domain in domains:
        dmarc_record = lookup_dmarc(domain)
        if not dmarc_record:
            txt_value = template.replace('[domain]', domain)
            lines.append(f"{domain},_dmarc.{domain},TXT,{txt_value}")
    
    return jsonify({'content': '\n'.join(lines), 'count': len(lines)})

@app.route('/api/domain_checker/spf_generate', methods=['POST'])
@login_required
def api_spf_generate():
    """Generate SPF records with support for IPs, A records, and Include records"""
    if not current_user.has_domain_checker_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    domains_text = data.get('domains', '')
    prefixed_domains_text = data.get('prefixed_domains', '')
    spf_type = data.get('spf_type', 'ips')
    distribute = data.get('distribute', False)
    
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    prefixed_domains = [d.strip().lower() for d in prefixed_domains_text.strip().split('\n') if d.strip()]
    
    if not domains:
        return jsonify({'error': 'No valid domains provided'}), 400
    
    if spf_type == 'ips' and prefixed_domains and len(prefixed_domains) != len(domains):
        return jsonify({'error': f'Number of prefixed domains ({len(prefixed_domains)}) must match number of domains ({len(domains)})'}), 400
    
    warning = None
    lines = []
    
    if spf_type == 'ips':
        ips_text = data.get('ips', '')
        ips = [ip.strip() for ip in ips_text.strip().split('\n') if ip.strip() and is_valid_ip(ip.strip())]
        
        if not ips:
            return jsonify({'error': 'No valid IP addresses provided'}), 400
        
        if len(ips) > 50:
            warning = f"Warning: {len(ips)} IPs provided. This may exceed SPF lookup limits."
        
        if distribute:
            if len(ips) < len(domains):
                return jsonify({'error': f'Not enough IPs ({len(ips)}) to distribute among {len(domains)} domains'}), 400
            
            ips_per_domain = len(ips) // len(domains)
            extra_ips = len(ips) % len(domains)
            ip_index = 0
            
            for i, domain in enumerate(domains):
                count = ips_per_domain + (1 if i < extra_ips else 0)
                domain_ips = ips[ip_index:ip_index + count]
                ip_index += count
                
                ip_parts = ' '.join([f'ip4:{ip}' for ip in domain_ips])
                spf_record = f'v=spf1 {ip_parts} -all'
                
                full_domain = prefixed_domains[i] if prefixed_domains else domain
                lines.append(f"{domain},{full_domain},TXT,{spf_record}")
        else:
            ip_parts = ' '.join([f'ip4:{ip}' for ip in ips])
            spf_record = f'v=spf1 {ip_parts} -all'
            
            for i, domain in enumerate(domains):
                full_domain = prefixed_domains[i] if prefixed_domains else domain
                lines.append(f"{domain},{full_domain},TXT,{spf_record}")
    
    elif spf_type == 'a_records':
        a_subdomains_text = data.get('a_subdomains', '')
        a_subdomain_lines = [line.strip() for line in a_subdomains_text.strip().split('\n') if line.strip()]
        
        if not a_subdomain_lines:
            return jsonify({'error': 'No subdomains provided for A records'}), 400
        
        # Validate subdomain lines count: must be exactly 1 OR equal to number of domains
        if len(a_subdomain_lines) != 1 and len(a_subdomain_lines) != len(domains):
            return jsonify({'error': f'Number of subdomain lines ({len(a_subdomain_lines)}) must be either 1 (to apply to all domains) or exactly {len(domains)} (to match each domain)'}), 400
        
        for i, domain in enumerate(domains):
            if i < len(a_subdomain_lines):
                subdomains_for_domain = [s.strip() for s in a_subdomain_lines[i].split(';') if s.strip()]
            else:
                subdomains_for_domain = [s.strip() for s in a_subdomain_lines[-1].split(';') if s.strip()]
            
            # Get the prefix from prefixed_domains (format: prefix.domain or just domain)
            full_domain = prefixed_domains[i] if i < len(prefixed_domains) and prefixed_domains else domain
            
            # Build a: parts with subdomain.prefix.domain format
            # Check if full_domain has a prefix (ends with .domain)
            if full_domain.endswith('.' + domain) and full_domain != domain:
                # Has prefix - extract it (e.g., mail.example.com -> mail)
                prefix = full_domain[:-len('.' + domain)]
                a_parts = ' '.join([f'a:{sub}' for sub in subdomains_for_domain])
            else:
                # No prefix - just use subdomain.domain
                a_parts = ' '.join([f'a:{sub}' for sub in subdomains_for_domain])
            
            spf_record = f'v=spf1 {a_parts} -all'
            lines.append(f"{domain},{full_domain},TXT,{spf_record}")
    
    elif spf_type == 'includes':
        include_domains_text = data.get('include_domains', '')
        include_domain_lines = [line.strip() for line in include_domains_text.strip().split('\n') if line.strip()]
        
        if not include_domain_lines:
            return jsonify({'error': 'No include domains provided'}), 400
        
        for i, domain in enumerate(domains):
            if i < len(include_domain_lines):
                includes_for_domain = [s.strip() for s in include_domain_lines[i].split(';') if s.strip()]
            else:
                includes_for_domain = [s.strip() for s in include_domain_lines[-1].split(';') if s.strip()]
            
            include_parts = ' '.join([f'include:{inc}' for inc in includes_for_domain])
            spf_record = f'v=spf1 {include_parts} -all'
            
            # Format: _spf.domain (no prefix before _spf)
            spf_subdomain = f'_spf.{domain}'
            full_domain = prefixed_domains[i] if i < len(prefixed_domains) and prefixed_domains else domain
            lines.append(f"{domain},{full_domain},TXT,{spf_record}")
    
    else:
        return jsonify({'error': 'Invalid SPF type specified'}), 400
    
    return jsonify({'content': '\n'.join(lines), 'count': len(lines), 'warning': warning})

@app.route('/api/domain_checker/a_generate', methods=['POST'])
@login_required
def api_a_generate():
    """Generate A record entries"""
    if not current_user.has_domain_checker_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    domains_text = data.get('domains', '')
    subdomain = data.get('subdomain', '').strip()
    ips_text = data.get('ips', '')
    
    if not subdomain:
        return jsonify({'error': 'Subdomain prefix is required for A records'}), 400
    
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    ips = list(set([ip.strip() for ip in ips_text.strip().split('\n') if ip.strip() and is_valid_ip(ip.strip())]))
    
    if not domains:
        return jsonify({'error': 'No valid domains provided'}), 400
    if not ips:
        return jsonify({'error': 'No valid IP addresses provided'}), 400
    
    warning = None
    if len(ips) > 50:
        warning = f"Warning: {len(ips)} unique IPs provided."
    
    lines = []
    ips_str = ';'.join(ips)
    
    for domain in domains:
        full_domain = f"{subdomain}.{domain}"
        lines.append(f"{domain},{full_domain},TXT,Arecords:{ips_str}")
    
    return jsonify({'content': '\n'.join(lines), 'count': len(lines), 'warning': warning})

@app.route('/api/domain_checker/mx', methods=['POST'])
@login_required
def api_mx_lookup():
    """API endpoint for MX lookups"""
    if not current_user.has_domain_checker_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    domains_text = data.get('domains', '')
    
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    
    results = []
    for domain in domains:
        mx_records = lookup_mx(domain)
        results.append({
            'domain': domain,
            'mx': mx_records if mx_records else ['Not Found']
        })
    
    return jsonify({'results': results})

@app.route('/api/domain_checker/mx_stream')
@login_required
def api_mx_stream():
    """SSE endpoint for MX lookups with progress updates"""
    if not current_user.has_domain_checker_permission:
        return Response("Permission denied", status=403)
    
    domains_text = request.args.get('domains', '')
    domains_text = urllib.parse.unquote(domains_text)
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    
    def generate():
        total = len(domains)
        results = [None] * total
        completed = [0]
        
        max_workers = min(20, total) if total else 1
        
        def process_domain(idx, domain):
            mx_records = lookup_mx(domain)
            return idx, {
                'domain': domain,
                'mx': mx_records if mx_records else ['Not Found']
            }
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {executor.submit(process_domain, i, d): i for i, d in enumerate(domains)}
            for future in as_completed(future_to_idx):
                try:
                    idx, result = future.result()
                    results[idx] = result
                    completed[0] += 1
                    yield f"data: {json.dumps({'type': 'progress', 'current': completed[0], 'total': total})}\n\n"
                except Exception:
                    idx = future_to_idx[future]
                    results[idx] = {'domain': domains[idx], 'mx': ['Not Found']}
                    completed[0] += 1
                    yield f"data: {json.dumps({'type': 'progress', 'current': completed[0], 'total': total})}\n\n"
        
        yield f"data: {json.dumps({'type': 'complete', 'results': results})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

@app.route('/api/domain_checker/txt', methods=['POST'])
@login_required
def api_txt_lookup():
    """API endpoint for TXT lookups"""
    if not current_user.has_domain_checker_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    data = request.get_json()
    domains_text = data.get('domains', '')
    
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    
    results = []
    for domain in domains:
        txt_records = lookup_txt(domain)
        results.append({
            'domain': domain,
            'txt': txt_records if txt_records else ['Not Found']
        })
    
    return jsonify({'results': results})

@app.route('/api/domain_checker/txt_stream')
@login_required
def api_txt_stream():
    """SSE endpoint for TXT lookups with progress updates"""
    if not current_user.has_domain_checker_permission:
        return Response("Permission denied", status=403)
    
    domains_text = request.args.get('domains', '')
    domains_text = urllib.parse.unquote(domains_text)
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    
    def generate():
        total = len(domains)
        results = [None] * total
        completed = [0]
        
        max_workers = min(20, total) if total else 1
        
        def process_domain(idx, domain):
            txt_records = lookup_txt(domain)
            return idx, {
                'domain': domain,
                'txt': txt_records if txt_records else ['Not Found']
            }
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {executor.submit(process_domain, i, d): i for i, d in enumerate(domains)}
            for future in as_completed(future_to_idx):
                try:
                    idx, result = future.result()
                    results[idx] = result
                    completed[0] += 1
                    yield f"data: {json.dumps({'type': 'progress', 'current': completed[0], 'total': total})}\n\n"
                except Exception:
                    idx = future_to_idx[future]
                    results[idx] = {'domain': domains[idx], 'txt': ['Not Found']}
                    completed[0] += 1
                    yield f"data: {json.dumps({'type': 'progress', 'current': completed[0], 'total': total})}\n\n"
        
        yield f"data: {json.dumps({'type': 'complete', 'results': results})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

@app.route('/tssw_rapport')
@login_required
def tssw_rapport():
    """TSSW Rapport service - only for users with tssw_report permission"""
    if not current_user.has_tssw_report_permission:
        flash('You do not have permission to access this service.', 'error')
        return redirect(url_for('services'))
    return render_template('tssw_rapport.html', current_user=current_user)

@app.route('/api/domain_checker/unified_lookup')
@login_required
def api_unified_lookup():
    """SSE endpoint for unified domain lookup with MX, TXT, SPF, A IP records"""
    if not current_user.has_domain_checker_permission:
        return Response("Permission denied", status=403)
    
    domains_text = request.args.get('domains', '')
    domains_text = urllib.parse.unquote(domains_text)
    check_mx = request.args.get('check_mx', 'false') == 'true'
    check_txt = request.args.get('check_txt', 'false') == 'true'
    check_spf = request.args.get('check_spf', 'false') == 'true'
    check_a = request.args.get('check_a', 'false') == 'true'
    
    domains = [d.strip().lower() for d in domains_text.strip().split('\n') if d.strip()]
    
    def lookup_a_records(domain):
        """Lookup A records (IP addresses) for a domain"""
        try:
            resolver = get_dns_resolver()
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
            return None
        except Exception as e:
            logging.debug(f"A lookup error for {domain}: {e}")
            return None
    
    def lookup_spf_record(domain):
        """Lookup SPF record for a domain"""
        try:
            resolver = get_dns_resolver()
            answers = resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_parts = []
                for s in rdata.strings:
                    if isinstance(s, bytes):
                        txt_parts.append(s.decode('utf-8', errors='replace'))
                    else:
                        txt_parts.append(str(s))
                txt_value = ''.join(txt_parts)
                if txt_value.lower().startswith('v=spf1'):
                    return txt_value
            return None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.resolver.Timeout):
            return None
        except Exception as e:
            logging.debug(f"SPF lookup error for {domain}: {e}")
            return None
    
    def process_domain(idx, domain):
        result = {'domain': domain}
        if check_mx:
            mx_records = lookup_mx(domain)
            result['mx'] = mx_records if mx_records else None
            result['mx_found'] = mx_records is not None and len(mx_records) > 0
        if check_txt:
            txt_records = lookup_txt(domain)
            result['txt'] = txt_records if txt_records else None
            result['txt_found'] = txt_records is not None and len(txt_records) > 0
        if check_spf:
            spf_record = lookup_spf_record(domain)
            result['spf'] = spf_record
            result['spf_found'] = spf_record is not None
        if check_a:
            a_records = lookup_a_records(domain)
            result['a'] = a_records if a_records else None
            result['a_found'] = a_records is not None and len(a_records) > 0
        return idx, result
    
    def generate():
        total = len(domains)
        results = [None] * total
        completed = [0]
        
        max_workers = min(20, total) if total else 1
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {executor.submit(process_domain, i, d): i for i, d in enumerate(domains)}
            for future in as_completed(future_to_idx):
                try:
                    idx, result = future.result()
                    results[idx] = result
                    completed[0] += 1
                    yield f"data: {json.dumps({'type': 'progress', 'current': completed[0], 'total': total})}\n\n"
                except Exception:
                    idx = future_to_idx[future]
                    result = {'domain': domains[idx]}
                    if check_mx:
                        result['mx'] = None
                        result['mx_found'] = False
                    if check_txt:
                        result['txt'] = None
                        result['txt_found'] = False
                    if check_spf:
                        result['spf'] = None
                        result['spf_found'] = False
                    if check_a:
                        result['a'] = None
                        result['a_found'] = False
                    results[idx] = result
                    completed[0] += 1
                    yield f"data: {json.dumps({'type': 'progress', 'current': completed[0], 'total': total})}\n\n"
        
        yield f"data: {json.dumps({'type': 'complete', 'results': results})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

@app.route('/blacklist_lookup')
@login_required
def blacklist_lookup():
    """Blacklist Lookup Service"""
    if not current_user.has_blacklist_lookup_permission:
        return redirect(url_for('services'))
    return render_template('blacklist_lookup.html')

# Spamhaus DQS Key from environment (with fallback like ipchecker.py)
DQS_KEY = os.environ.get("DQS_KEY", "f3jqdoqpeyipweiizk7onufnlm")
print(f"[BLACKLIST] DQS_KEY loaded: {DQS_KEY[:8]}... (length: {len(DQS_KEY)})")

# Regex patterns for validation (same as ipchecker.py)
import re
IP_REGEX = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DOMAIN_REGEX = re.compile(r"^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")

def check_spamhaus_ip(ip):
    """Check IP against Spamhaus blocklists - EXACT copy from ipchecker.py"""
    try:
        rev = ".".join(ip.split(".")[::-1])
        query = f"{rev}.{DQS_KEY}.zen.dq.spamhaus.net"
        print(f"[DEBUG] Querying: {query}")
        answers = blacklist_resolver.resolve(query, "A")
        found = {r.to_text() for r in answers}
        print(f"[DEBUG] IP {ip} -> Answers: {found}")

        if "127.0.0.3" in found:
            return "css"
        if "127.0.0.2" in found or "127.0.0.9" in found:
            return "sbl"
        if found.intersection({"127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7"}):
            return "xbl"
        if "127.0.0.10" in found or "127.0.0.11" in found:
            return "pbl"
        if any(r.startswith("127.0.0.") for r in found):
            return "sbl"
        return None
    except dns.resolver.NXDOMAIN:
        print(f"[DEBUG] IP {ip} -> NXDOMAIN (clean)")
        return "clean"
    except Exception as e:
        print(f"[DEBUG] IP {ip} -> Exception: {e}")
        return None

def check_barracuda(ip):
    """Check IP against Barracuda blocklist - EXACT copy from ipchecker.py"""
    try:
        rev = ".".join(ip.split(".")[::-1])
        query = f"{rev}.b.barracudacentral.org"
        blacklist_resolver.resolve(query, "A")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        return False

def check_spamhaus_domain(domain):
    """Check domain against Spamhaus DBL - EXACT copy from ipchecker.py"""
    try:
        query = f"{domain}.{DQS_KEY}.dbl.dq.spamhaus.net"
        answers = blacklist_resolver.resolve(query, "A")
        if any(r.to_text().startswith("127.0.1.") for r in answers):
            return "dbl"
        return None
    except dns.resolver.NXDOMAIN:
        return "clean"
    except Exception:
        return None

def check_single_entry(entry_data):
    """Check a single IP/domain entry against all blacklists - for parallel processing
    Uses EXACT same logic as ipchecker.py process_item function"""
    idx, serveur, ip, domain, status = entry_data
    
    # Initialize result
    result = {
        'idx': idx,
        'serveur': serveur,
        'ip': ip if ip else '',
        'domain': domain if domain else '',
        'status': status,
        'css': 'Clean',
        'pbl': 'Clean',
        'xbl': 'Clean',
        'sbl': 'Clean',
        'barracuda': 'Clean',
        'dbl': 'Clean'
    }
    
    # Check IP blocklists only if IP is provided (same logic as ipchecker.py)
    if ip:
        spamhaus_ip = check_spamhaus_ip(ip)
        barracuda = check_barracuda(ip)
        
        # Map spamhaus result to the correct column
        if spamhaus_ip and spamhaus_ip != "clean":
            result[spamhaus_ip] = 'Listed'
        
        if barracuda:
            result['barracuda'] = 'Listed'
    
    # Check domain blocklist only if domain is provided
    if domain:
        dbl_result = check_spamhaus_domain(domain)
        if dbl_result == "dbl":
            result['dbl'] = 'Listed'
    
    return result

@app.route('/api/check_blacklists_stream', methods=['POST'])
@login_required
def check_blacklists_stream():
    """SSE streaming endpoint for blacklist checks with parallel processing"""
    if not current_user.has_blacklist_lookup_permission:
        return jsonify({'error': 'Permission denied'}), 403
    
    try:
        data = request.get_json()
        lines = data.get('lines', [])
        
        if not lines:
            return jsonify({'error': 'No data provided'}), 400
        
        # Parse and validate all lines using same logic as ipchecker.py
        valid_entries = []
        errors = []
        
        for idx, line in enumerate(lines):
            line = line.strip()
            
            if not line:
                continue
            
            # Split on colons - support multiple formats like ipchecker.py
            parts = line.split(":")
            
            serveur = ""
            ip = ""
            domain = ""
            status = ""
            
            if len(parts) == 4:
                # Format: SERVEUR:IP:DOMAIN:STATUS
                serveur = parts[0].strip()
                ip = parts[1].strip()
                domain = parts[2].strip()
                status = parts[3].strip()
            elif len(parts) == 3:
                # Format: SERVEUR:IP:DOMAIN
                serveur = parts[0].strip()
                ip = parts[1].strip()
                domain = parts[2].strip()
                status = ""
            elif len(parts) == 2:
                # Format: SERVEUR:VALUE (IP or Domain)
                serveur = parts[0].strip()
                value = parts[1].strip()
                if IP_REGEX.match(value):
                    ip = value
                    domain = ""
                elif DOMAIN_REGEX.match(value):
                    ip = ""
                    domain = value
                else:
                    errors.append(f"Line {idx + 1}: Invalid IP or domain '{value}'")
                    continue
            elif len(parts) == 1:
                # Format: Just IP or Domain
                value = parts[0].strip()
                if IP_REGEX.match(value):
                    serveur = "unknown"
                    ip = value
                    domain = ""
                elif DOMAIN_REGEX.match(value):
                    serveur = "unknown"
                    ip = ""
                    domain = value
                else:
                    errors.append(f"Line {idx + 1}: Invalid format")
                    continue
            else:
                errors.append(f"Line {idx + 1}: Too many colons in line")
                continue
            
            # Validate IP format if provided
            if ip:
                if not IP_REGEX.match(ip):
                    errors.append(f"Line {idx + 1}: Invalid IP '{ip}'")
                    continue
            
            # Validate domain format if provided
            if domain:
                if not DOMAIN_REGEX.match(domain):
                    errors.append(f"Line {idx + 1}: Invalid domain '{domain}'")
                    continue
            
            # Need at least IP or domain
            if not ip and not domain:
                errors.append(f"Line {idx + 1}: No valid IP or domain found")
                continue
            
            valid_entries.append((idx, serveur, ip, domain, status))
        
        total = len(valid_entries)
        
        def generate():
            yield f"data: {json.dumps({'type': 'start', 'total': total, 'errors': errors})}\n\n"
            
            results = []
            completed = 0
            
            # Use ThreadPoolExecutor for parallel processing (20 concurrent to avoid DNS rate limiting)
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(check_single_entry, entry): entry for entry in valid_entries}
                
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logging.debug(f"Error processing entry: {e}")
                    
                    completed += 1
                    yield f"data: {json.dumps({'type': 'progress', 'current': completed, 'total': total})}\n\n"
            
            # Sort results by original index
            results.sort(key=lambda x: x['idx'])
            # Remove idx from results
            for r in results:
                del r['idx']
            
            yield f"data: {json.dumps({'type': 'complete', 'results': results})}\n\n"
        
        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive'
            }
        )
    
    except Exception as e:
        logging.error(f"Error in check_blacklists_stream: {e}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

application = app