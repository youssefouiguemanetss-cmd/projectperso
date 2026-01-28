import os
import json
import random
import re
import time
import requests
import shutil
import threading
import logging
from datetime import datetime

USER_DATA_DIR = "quality_helper_data"
os.makedirs(USER_DATA_DIR, exist_ok=True)

MIN_IMAGE_SIZE = 60 * 1024
MAX_IMAGE_SIZE = 200 * 1024
SKIP_EXTENSIONS = [".webp"]

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/132.0.0.0 Safari/537.36"
)

SERVICE_PHRASES = [
    "web design service",
    "app development service",
    "seo optimization service",
    "digital marketing service",
    "content writing service",
    "graphic design service",
    "video editing service",
    "business consulting service",
    "house cleaning service",
    "coffee delivery service",
    "restaurant takeout service",
]

SUBJECT_TEMPLATES = [
    "How a {service} helped a business grow fast",
    "Why one company invested in a {service}",
    "When a brand realized it needed a {service}",
    "How a small team scaled using a {service}",
    "What changed after switching to a {service}",
]

user_processes = {}
user_process_locks = {}

def get_user_lock(username):
    if username not in user_process_locks:
        user_process_locks[username] = threading.Lock()
    return user_process_locks[username]

def get_user_dir(username):
    user_dir = os.path.join(USER_DATA_DIR, username)
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def get_user_images_dir(username):
    images_dir = os.path.join(get_user_dir(username), "images")
    os.makedirs(images_dir, exist_ok=True)
    return images_dir

def get_user_data_file(username):
    return os.path.join(get_user_dir(username), "process_data.json")

def generate_subject():
    return random.choice(SUBJECT_TEMPLATES).format(
        service=random.choice(SERVICE_PHRASES)
    )

def clean_filename(text):
    text = re.sub(r"[^\w\s-]", "", text)
    return text.replace(" ", "_")

def get_user_process_status(username):
    data_file = get_user_data_file(username)
    if os.path.exists(data_file):
        try:
            with open(data_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except:
            return None
    return None

def save_user_process_data(username, data):
    data_file = get_user_data_file(username)
    with open(data_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

def is_process_running(username):
    return username in user_processes and user_processes[username].get('running', False)

def delete_user_process(username):
    user_dir = get_user_dir(username)
    if os.path.exists(user_dir):
        shutil.rmtree(user_dir)
    if username in user_processes:
        del user_processes[username]
    return True

def run_image_generation(username, keywords, total_images):
    from playwright.sync_api import sync_playwright
    
    user_processes[username] = {
        'running': True,
        'progress': 0,
        'total': total_images,
        'status': 'Starting...',
        'error': None
    }
    
    try:
        images_dir = get_user_images_dir(username)
        
        if len(keywords) < total_images:
            user_processes[username]['error'] = f"Not enough keywords ({len(keywords)}) for {total_images} images"
            user_processes[username]['running'] = False
            return
        
        selected_keywords = random.sample(keywords, total_images)
        
        subjects = []
        image_data = []
        
        user_processes[username]['status'] = 'Starting browser...'
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(user_agent=UA)
            page = context.new_page()
            
            for idx, keyword in enumerate(selected_keywords):
                if not user_processes.get(username, {}).get('running', False):
                    break
                    
                user_processes[username]['status'] = f'Searching: {keyword}'
                
                try:
                    # Faster search URL
                    page.goto(
                        f"https://www.bing.com/images/search?q={keyword}&first=1",
                        wait_until="commit",
                        timeout=30000,
                    )
                    
                    page.wait_for_selector("a.iusc", timeout=10000)
                    results = page.query_selector_all("a.iusc")
                    random.shuffle(results)
                    
                    for item in results[:10]:
                        data_m = item.get_attribute("m")
                        if not data_m:
                            continue
                        
                        try:
                            meta = json.loads(data_m)
                            img_url = meta.get("murl")
                        except:
                            continue
                        
                        if not img_url or not img_url.startswith("http"):
                            continue
                        
                        try:
                            r = requests.get(
                                img_url,
                                headers={
                                    "User-Agent": UA,
                                    "Referer": "https://www.bing.com/",
                                },
                                timeout=10,
                            )
                            
                            ct = r.headers.get("Content-Type", "").lower()
                            size = len(r.content)
                            
                            if (
                                not r.ok
                                or "image" not in ct
                                or size < MIN_IMAGE_SIZE
                                or size > MAX_IMAGE_SIZE
                            ):
                                continue
                            
                            ext = ".png" if "png" in ct else ".jpg"
                            subject = generate_subject()
                            filename = f"{clean_filename(subject)}{ext}"
                            path = os.path.join(images_dir, filename)
                            
                            with open(path, "wb") as f:
                                f.write(r.content)
                            
                            image_data.append({
                                'filename': filename,
                                'url': img_url,
                                'keyword': keyword,
                                'subject': subject,
                                'size_kb': size // 1024
                            })
                            subjects.append(subject)
                            user_processes[username]['progress'] += 1
                            break # Found one, move to next keyword
                            
                        except:
                            continue
                except Exception as e:
                    logging.error(f"Error searching for {keyword}: {e}")
                    continue

            browser.close()
        
        process_data = {
            'status': 'completed',
            'created_at': datetime.now().isoformat(),
            'keywords_used': selected_keywords,
            'total_requested': total_images,
            'total_fetched': len(image_data),
            'subjects': subjects,
            'images': image_data,
            'image_links': [img['filename'] for img in image_data]
        }
        
        save_user_process_data(username, process_data)
        
        user_processes[username]['progress'] = total_images
        user_processes[username]['status'] = 'Completed'
        user_processes[username]['running'] = False
        
    except Exception as e:
        logging.error(f"Error in image generation for {username}: {e}")
        user_processes[username]['error'] = str(e)
        user_processes[username]['running'] = False
