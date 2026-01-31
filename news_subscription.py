import os
import json
import random
import re
import time
import asyncio
import threading
import logging
import traceback
from datetime import datetime
from faker import Faker

USER_DATA_DIR = "news_subscription_data"
os.makedirs(USER_DATA_DIR, exist_ok=True)

fake = Faker()

CONFIG = {
    'page_timeout': 30000,
    'element_timeout': 10000,
    'wait_after_click': 3000,
    'wait_between_domains': (3000, 8000),
    'max_retries': 2,
    'navigation_timeout': 30000,
    'form_fill_delay': 800,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]
}

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

def get_user_data_file(username):
    return os.path.join(get_user_dir(username), "process_data.json")

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

def stop_user_process(username):
    if username in user_processes:
        user_processes[username]['running'] = False
        user_processes[username]['status'] = 'Stopped by user'
    return True

def delete_user_process(username):
    user_dir = get_user_dir(username)
    if os.path.exists(user_dir):
        import shutil
        shutil.rmtree(user_dir)
    if username in user_processes:
        del user_processes[username]
    return True

def generate_password(length=12):
    import string
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    password = [
        random.choice(uppercase),
        random.choice(lowercase),
        random.choice(digits),
        random.choice(special)
    ]
    
    all_chars = uppercase + lowercase + digits + special
    for _ in range(length - 4):
        password.append(random.choice(all_chars))
    
    random.shuffle(password)
    return ''.join(password)

async def is_registration_related(text, href=None):
    if not text or len(text.strip()) < 2:
        return False
    
    text_lower = text.lower().strip()
    
    negative_keywords = ['log in', 'login', 'sign in', 'signin', 'sign-in']
    for keyword in negative_keywords:
        if keyword in text_lower:
            return False
    
    primary_keywords = [
        'sign up', 'signup', 'sign-up', 'register', 'registration', 'create account',
        'create free account', 'join now', 'get started', 'subscribe', 'newsletter',
        'email signup', 'free account', 'start now', 'enroll', 'join free',
        'become member', 'new account', 'get access', 'start free trial'
    ]
    
    third_party_keywords = ['google', 'facebook', 'twitter', 'apple', 'oauth', 'with', 'github']
    
    for keyword in primary_keywords:
        if keyword in text_lower:
            if any(tp in text_lower for tp in third_party_keywords):
                return False
            return True
    
    if href:
        href_lower = href.lower()
        href_keywords = [
            '/signup', '/sign-up', '/register', '/registration', '/join',
            '/subscribe', '/create/account', '/account/create', '/enroll'
        ]
        for keyword in href_keywords:
            if keyword in href_lower:
                if any(tp in href_lower for tp in third_party_keywords):
                    return False
                return True
    
    return False

async def get_element_info(element):
    try:
        if not await element.is_visible():
            return None, None
        
        text = ''
        methods = [
            ('inner_text', lambda: element.inner_text(timeout=3000)),
            ('text_content', lambda: element.text_content()),
            ('value', lambda: element.get_attribute('value')),
            ('aria-label', lambda: element.get_attribute('aria-label')),
            ('title', lambda: element.get_attribute('title')),
            ('alt', lambda: element.get_attribute('alt')),
            ('placeholder', lambda: element.get_attribute('placeholder')),
        ]
        
        for method_name, method in methods:
            try:
                result = await method()
                if result and result.strip():
                    text = result.strip()
                    break
            except:
                continue
        
        href = None
        try:
            href = await element.get_attribute('href')
        except:
            pass
        
        return text, href
        
    except Exception as e:
        return None, None

async def check_domain_relevance(page):
    try:
        await page.wait_for_timeout(2000)
        page_text = (await page.inner_text('body', timeout=8000)).lower()
        
        required_keywords = [
            'create account', 'login', 'log in', 'sign in', 'sign up',
            'signup', 'free trial', 'register', 'registration', 'subscribe',
            'newsletter', 'email'
        ]
        
        for keyword in required_keywords:
            if keyword in page_text:
                return True
        
        return False
        
    except Exception as e:
        return False

async def safe_click(element, page, timeout=5000, force=False, is_check=False):
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    try:
        async with page.expect_popup(timeout=timeout) as popup_info:
            if is_check:
                if force:
                    await element.check(force=True, timeout=timeout)
                else:
                    await element.check(timeout=timeout)
            else:
                if force:
                    await element.click(force=True, timeout=timeout)
                else:
                    await element.click(timeout=timeout)
        
        popup = await popup_info.value
        if popup:
            old_page = page
            page = popup
            await page.wait_for_load_state('domcontentloaded', timeout=10000)
            await old_page.close()
            return page, True
    except PlaywrightTimeoutError:
        pass
    except Exception as e:
        pass
    
    return page, False

async def find_registration_elements(page):
    try:
        await page.wait_for_load_state('domcontentloaded', timeout=10000)
        await page.wait_for_timeout(3000)
        
        registration_elements = []
        
        element_selectors = [
            'a:has-text("Register"):visible',
            'a:has-text("Sign Up"):visible',
            'a:has-text("Sign up"):visible',
            'a:has-text("Subscribe"):visible',
            'a:has-text("Newsletter"):visible',
            'button:has-text("Register"):visible',
            'button:has-text("Sign Up"):visible',
            'button:has-text("Subscribe"):visible',
            'button:has-text("Join"):visible',
            'button:has-text("Get Started"):visible',
            'a[href*="register" i]:visible',
            'a[href*="signup" i]:visible',
            'a[href*="subscribe" i]:visible',
            'input[type="submit"][value*="register" i]:visible',
            'input[type="submit"][value*="sign up" i]:visible',
            'input[type="submit"][value*="subscribe" i]:visible'
        ]
        
        processed_elements = set()
        
        for selector in element_selectors:
            try:
                elements = await asyncio.wait_for(
                    page.query_selector_all(selector),
                    timeout=5.0
                )
                
                for element in elements[:5]:
                    try:
                        element_id = await asyncio.wait_for(
                            element.evaluate('el => el.outerHTML.substring(0, 100)'),
                            timeout=2.0
                        )
                        if element_id in processed_elements:
                            continue
                        processed_elements.add(element_id)
                        
                        if not await element.is_visible():
                            continue
                        
                        text, href = await get_element_info(element)
                        if text and await is_registration_related(text, href):
                            registration_elements.append((element, text, href or ''))
                            
                            if len(registration_elements) >= 6:
                                break
                    except asyncio.TimeoutError:
                        continue
                    except Exception as e:
                        continue
                        
                if len(registration_elements) >= 6:
                    break
                    
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue
        
        return registration_elements[:6]
        
    except Exception as e:
        return []

async def smart_form_fill(page, email):
    try:
        try:
            await page.wait_for_load_state('domcontentloaded', timeout=10000)
        except Exception as e:
            pass
        
        await page.wait_for_timeout(3000)
        
        username = fake.user_name().lower() + str(random.randint(100, 999))
        password = generate_password(16)
        first_name = fake.first_name()
        last_name = fake.last_name()
        full_name = f"{first_name} {last_name}"
        
        filled_count = 0
        
        try:
            all_form_elements = await page.query_selector_all(
                'input:not([type="hidden"]):not([disabled]):visible, '
                'textarea:not([disabled]):visible, '
                'select:not([disabled]):visible'
            )
            
            for i, element in enumerate(all_form_elements):
                try:
                    if not await element.is_visible():
                        continue
                    
                    input_type = 'text'
                    input_name = ''
                    input_id = ''
                    input_placeholder = ''
                    tag_name = ''
                    
                    try:
                        tag_name = await element.evaluate('el => el.tagName.toLowerCase()')
                        input_type = (await element.get_attribute('type') or 'text').lower()
                        input_name = (await element.get_attribute('name') or '').lower()
                        input_id = (await element.get_attribute('id') or '').lower()
                        input_placeholder = (await element.get_attribute('placeholder') or '').lower()
                    except Exception as e:
                        pass
                    
                    field_context = f"{input_name} {input_id} {input_placeholder}".lower()
                    
                    try:
                        current_value = await element.get_attribute('value') or ''
                        if current_value.strip() and len(current_value.strip()) > 2:
                            continue
                    except:
                        pass
                    
                    filled = False
                    
                    if tag_name == 'select':
                        try:
                            options = await element.query_selector_all('option')
                            if len(options) > 1:
                                valid_options = []
                                for option in options[1:]:
                                    value = await option.get_attribute('value')
                                    if value and value.strip():
                                        valid_options.append(value)
                                
                                if valid_options:
                                    selected_value = random.choice(valid_options)
                                    await element.select_option(selected_value)
                                    filled = True
                        except Exception as e:
                            pass
                    
                    else:
                        try:
                            page, _ = await safe_click(element, page)
                            await element.fill('')
                            await page.wait_for_timeout(300)
                            
                            if input_type == 'email' or 'email' in field_context:
                                await element.fill(email)
                                filled = True
                            
                            elif input_type == 'password':
                                await element.fill(password)
                                filled = True
                            
                            elif ('username' in field_context or 'login' in field_context) and input_type != 'password':
                                await element.fill(username)
                                filled = True
                            
                            elif 'first' in field_context and 'name' in field_context:
                                await element.fill(first_name)
                                filled = True
                            elif 'last' in field_context and 'name' in field_context:
                                await element.fill(last_name)
                                filled = True
                            elif ('full' in field_context or 'name' in field_context) and 'email' not in field_context:
                                await element.fill(full_name)
                                filled = True
                            
                            elif 'phone' in field_context or 'mobile' in field_context:
                                phone = fake.phone_number()
                                await element.fill(phone)
                                filled = True
                            
                            elif 'company' in field_context or 'organization' in field_context:
                                company = fake.company()
                                await element.fill(company)
                                filled = True
                            
                            elif input_type == 'text' and not filled:
                                if any(word in field_context for word in ['search', 'query', 'keyword']):
                                    continue
                                else:
                                    await element.fill(full_name)
                                    filled = True
                            
                            elif tag_name == 'textarea':
                                message = f"Hello, I'm interested in your services. Please contact me at {email}. Thank you!"
                                await element.fill(message)
                                filled = True
                            
                        except Exception as e:
                            pass
                    
                    if filled:
                        filled_count += 1
                        await page.wait_for_timeout(500)
                    
                except Exception as e:
                    continue
        
        except Exception as e:
            pass
        
        try:
            checkboxes = await page.query_selector_all('input[type="checkbox"]:visible')
            for checkbox in checkboxes:
                try:
                    checkbox_name = (await checkbox.get_attribute('name') or '').lower()
                    checkbox_id = (await checkbox.get_attribute('id') or '').lower()
                    checkbox_context = f"{checkbox_name} {checkbox_id}".lower()
                    
                    if any(term in checkbox_context for term in
                          ['agree', 'terms', 'privacy', 'consent', 'accept', 'newsletter', 'updates']):
                        if not await checkbox.is_checked():
                            page, _ = await safe_click(checkbox, page, is_check=True)
                            filled_count += 1
                except Exception as e:
                    pass
                    
        except Exception as e:
            pass
        
        return filled_count
        
    except Exception as e:
        return 0

async def smart_form_submit(page):
    try:
        submit_selectors = [
            'button:has-text("Register"):visible',
            'button:has-text("Sign Up"):visible',
            'button:has-text("Subscribe"):visible',
            'button:has-text("Join"):visible',
            'input[type="submit"]:visible',
            'button[type="submit"]:visible',
            'input[value*="register" i]:visible',
            'input[value*="sign up" i]:visible',
            'input[value*="subscribe" i]:visible',
            'button:has-text("Submit"):visible',
            'button:has-text("Continue"):visible',
            'button:has-text("Get Started"):visible',
            '.btn-primary:visible',
            'form button:visible'
        ]
        
        submit_button = None
        button_text = ""
        third_party_keywords = ['google', 'facebook', 'twitter', 'apple', 'oauth', 'with', 'github']
        
        for selector in submit_selectors:
            try:
                submit_button = await page.query_selector(selector)
                if submit_button and await submit_button.is_visible():
                    button_text, _ = await get_element_info(submit_button)
                    if button_text and any(tp in button_text.lower() for tp in third_party_keywords):
                        continue
                    break
            except:
                continue
        
        if not submit_button:
            return False, page
        
        current_url = page.url
        
        try:
            await submit_button.scroll_into_view_if_needed()
            await page.wait_for_timeout(1000)
            page, _ = await safe_click(submit_button, page, timeout=10000, force=True)
        except Exception as e:
            return False, page
        
        await page.wait_for_timeout(5000)
        
        new_url = page.url
        new_title = await page.title()
        
        success_url_indicators = [
            'success', 'confirm', 'confirmation', 'thank', 'thanks', 'welcome',
            'verify', 'verification', 'activation', 'activate', 'registered',
            'complete', 'done', 'dashboard', 'account', 'profile', 'subscribed'
        ]
        
        if new_url != current_url:
            if any(indicator in new_url.lower() for indicator in success_url_indicators):
                return True, page
        
        if new_title:
            success_title_indicators = [
                'success', 'confirm', 'thank', 'welcome', 'verify', 'complete',
                'registration', 'account created', 'signed up', 'subscribed'
            ]
            if any(indicator in new_title.lower() for indicator in success_title_indicators):
                return True, page
        
        try:
            page_text = await page.inner_text('body', timeout=8000)
            page_text_lower = page_text.lower()
            
            success_indicators = [
                'thank you', 'thanks', 'success', 'successful', 'successfully',
                'welcome', 'registered', 'registration complete', 'subscribed',
                'subscription successful', 'confirmation', 'verify your email',
                'check your email', 'account created', 'signed up',
                'congratulations', 'almost done', 'please verify', 'activation',
                'confirm your subscription', 'welcome aboard', 'you\'re in',
                'registration successful', 'confirmation email sent'
            ]
            
            for indicator in success_indicators:
                if indicator in page_text_lower:
                    return True, page
                    
        except Exception as e:
            pass
        
        return True, page
        
    except Exception as e:
        return False, page

async def handle_popup_with_email(page, email):
    try:
        await page.wait_for_timeout(2000)
        
        popup_selectors = [
            '[role="dialog"]:visible',
            '.modal:visible',
            '.popup:visible',
            '[class*="modal" i]:visible',
            '[class*="popup" i]:visible',
            '[id*="modal" i]:visible',
            '[id*="popup" i]:visible',
            '.overlay:visible'
        ]
        
        popup = None
        for selector in popup_selectors:
            try:
                popup = await page.query_selector(selector)
                if popup and await popup.is_visible():
                    break
            except:
                continue
        
        if not popup:
            return False, page
        
        email_inputs = await popup.query_selector_all(
            'input[type="email"]:visible, input[name*="email" i]:visible, '
            'input[placeholder*="email" i]:visible'
        )
        
        has_email_field = False
        for email_input in email_inputs:
            if await email_input.is_visible():
                has_email_field = True
                break
        
        if not has_email_field:
            close_selectors = [
                'button[aria-label*="close" i]:visible',
                'button[title*="close" i]:visible',
                '[class*="close" i]:visible',
                'button:has-text("×"):visible',
                'button:has-text("Close"):visible',
            ]
            
            for selector in close_selectors:
                try:
                    close_btn = await popup.query_selector(selector)
                    if close_btn and await close_btn.is_visible():
                        page, _ = await safe_click(close_btn, page)
                        await page.wait_for_timeout(1000)
                        return True, page
                except:
                    continue
            
            try:
                await page.keyboard.press('Escape')
                await page.wait_for_timeout(1000)
                return True, page
            except:
                pass
        
        else:
            all_inputs = await popup.query_selector_all('input:visible, textarea:visible')
            
            for input_elem in all_inputs:
                try:
                    input_type = (await input_elem.get_attribute('type') or 'text').lower()
                    input_name = (await input_elem.get_attribute('name') or '').lower()
                    input_placeholder = (await input_elem.get_attribute('placeholder') or '').lower()
                    field_context = f"{input_name} {input_placeholder}".lower()
                    
                    if input_type == 'email' or 'email' in field_context:
                        await input_elem.fill(email)
                    elif 'name' in field_context and 'email' not in field_context:
                        await input_elem.fill(fake.name())
                    elif input_type == 'text':
                        await input_elem.fill(fake.name())
                    
                    await page.wait_for_timeout(500)
                except:
                    continue
            
            submit_selectors = [
                'button[type="submit"]:visible',
                'input[type="submit"]:visible',
                'button:has-text("Submit"):visible',
                'button:has-text("Subscribe"):visible',
                'button:has-text("Continue"):visible',
                'button:has-text("Sign up"):visible'
            ]
            
            for selector in submit_selectors:
                try:
                    submit_btn = await popup.query_selector(selector)
                    if submit_btn and await submit_btn.is_visible():
                        page, _ = await safe_click(submit_btn, page)
                        await page.wait_for_timeout(2000)
                        return True, page
                except:
                    continue
        
        return False, page
        
    except Exception as e:
        return False, page

async def registration_workflow(page, email, domain):
    try:
        max_workflow_steps = 2
        current_step = 0
        forms_found = 0
        fields_filled = 0
        made_progress = False
        
        while current_step < max_workflow_steps:
            current_step += 1
            current_url = page.url
            step_progress = False
            
            try:
                forms = await page.query_selector_all('form:visible')
                forms_found = len(forms)
                
                if forms:
                    fields_filled_count = await smart_form_fill(page, email)
                    fields_filled += fields_filled_count
                    
                    if fields_filled_count > 0:
                        step_progress = True
                        made_progress = True
                        
                        submission_result, page = await smart_form_submit(page)
                        
                        if submission_result:
                            return True, page
                    
            except Exception as e:
                pass
            
            if not step_progress:
                try:
                    popup_handled, page = await handle_popup_with_email(page, email)
                    
                    forms = await page.query_selector_all('form:visible')
                    if forms and forms_found < len(forms):
                        fields_filled_count = await smart_form_fill(page, email)
                        fields_filled += fields_filled_count
                        if fields_filled_count > 0:
                            submission_result, page = await smart_form_submit(page)
                            if submission_result:
                                return True, page
                    
                    reg_elements = await find_registration_elements(page)
                    
                    if reg_elements:
                        step_progress = True
                        made_progress = True
                        
                        elements_to_try = min(2, len(reg_elements))
                        
                        for i, (element, text, href) in enumerate(reg_elements[:elements_to_try]):
                            try:
                                await element.scroll_into_view_if_needed()
                                await page.wait_for_timeout(1000)
                                page, _ = await safe_click(element, page, timeout=10000)
                                
                                await page.wait_for_timeout(CONFIG['wait_after_click'])
                                
                                new_url = page.url
                                if new_url != current_url:
                                    await page.wait_for_timeout(2000)
                                    new_forms = await page.query_selector_all('form:visible')
                                    if new_forms and len(new_forms) > forms_found:
                                        fields_filled_count = await smart_form_fill(page, email)
                                        fields_filled += fields_filled_count
                                        if fields_filled_count > 0:
                                            submission_result, page = await smart_form_submit(page)
                                            if submission_result:
                                                return True, page
                                        break
                                    
                            except Exception as e:
                                continue
                    
                except Exception as e:
                    pass
            
            if not step_progress:
                if current_step >= 2 and not made_progress:
                    return False, page
            
            await page.wait_for_timeout(1500)
        
        return False, page
        
    except Exception as e:
        return False, page

async def process_domain(page, domain, email):
    url = domain if domain.startswith(('http://', 'https://')) else f"https://{domain}"
    
    max_retries = CONFIG['max_retries']
    relevance_checked = False
    
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                pass
            
            try:
                await page.goto(url, timeout=CONFIG['navigation_timeout'], wait_until='domcontentloaded')
            except Exception as nav_error:
                if attempt == max_retries - 1:
                    return False
                continue
            
            try:
                await page.wait_for_load_state('networkidle', timeout=15000)
            except:
                pass
            
            await page.wait_for_timeout(5000)
            
            if not relevance_checked:
                if not await check_domain_relevance(page):
                    return False
                relevance_checked = True
            
            await handle_popup_with_email(page, email)
            
            success, page = await registration_workflow(page, email, domain)
            
            if success:
                return True
            else:
                if attempt == max_retries - 1:
                    return False
                
        except Exception as e:
            if attempt == max_retries - 1:
                return False
            
        if attempt < max_retries - 1:
            retry_delay = random.randint(3000, 8000)
            await page.wait_for_timeout(retry_delay)
    
    return False

async def run_subscription_process_async(username, email, domains):
    from playwright.async_api import async_playwright
    
    user_processes[username] = {
        'running': True,
        'progress': 0,
        'total': len(domains),
        'status': 'Starting...',
        'error': None,
        'successful': 0,
        'failed': 0
    }
    
    try:
        successful_registrations = 0
        failed_registrations = 0
        
        user_processes[username]['status'] = 'Starting browser...'
        
        async with async_playwright() as p:
            for i, domain in enumerate(domains):
                if not user_processes.get(username, {}).get('running', False):
                    break
                
                user_processes[username]['status'] = f'Processing: {domain}'
                user_processes[username]['progress'] = i
                
                browser = await p.chromium.launch(
                    headless=True,
                    args=[
                        '--disable-blink-features=AutomationControlled',
                        '--disable-web-security',
                        '--no-sandbox',
                        '--disable-dev-shm-usage',
                        '--disable-gpu',
                        '--disable-software-rasterizer',
                        '--disable-extensions',
                        '--no-first-run',
                        '--window-size=1920,1080',
                    ],
                    slow_mo=300
                )
                
                context = await browser.new_context(
                    viewport={'width': 1920, 'height': 1080},
                    user_agent=random.choice(CONFIG['user_agents']),
                    java_script_enabled=True,
                    accept_downloads=False,
                    ignore_https_errors=True,
                    bypass_csp=True,
                    extra_http_headers={
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                        'Cache-Control': 'no-cache',
                    }
                )
                
                page = await context.new_page()
                
                try:
                    success = await process_domain(page, domain, email)
                    if success:
                        successful_registrations += 1
                    else:
                        failed_registrations += 1
                        
                except Exception as e:
                    failed_registrations += 1
                finally:
                    await page.close()
                    await context.close()
                    await browser.close()
                
                user_processes[username]['successful'] = successful_registrations
                user_processes[username]['failed'] = failed_registrations
                
                if i < len(domains) - 1 and user_processes.get(username, {}).get('running', False):
                    delay = random.randint(*CONFIG['wait_between_domains'])
                    user_processes[username]['status'] = f'Waiting before next domain...'
                    await asyncio.sleep(delay / 1000)
        
        total_processed = successful_registrations + failed_registrations
        success_rate = (successful_registrations / total_processed * 100) if total_processed > 0 else 0
        
        process_data = {
            'status': 'completed' if user_processes.get(username, {}).get('running', False) else 'stopped',
            'created_at': datetime.now().isoformat(),
            'successful_registrations': successful_registrations,
            'failed_registrations': failed_registrations,
            'success_rate': round(success_rate, 1),
            'total_domains_processed': total_processed,
            'email_used': email
        }
        
        save_user_process_data(username, process_data)
        
        user_processes[username]['progress'] = len(domains)
        user_processes[username]['status'] = 'Completed' if user_processes[username].get('running', False) else 'Stopped'
        user_processes[username]['running'] = False
        
    except Exception as e:
        logging.error(f"Error in subscription process for {username}: {e}")
        user_processes[username]['error'] = str(e)
        user_processes[username]['running'] = False
        
        total_processed = user_processes[username].get('successful', 0) + user_processes[username].get('failed', 0)
        success_rate = (user_processes[username].get('successful', 0) / total_processed * 100) if total_processed > 0 else 0
        
        process_data = {
            'status': 'error',
            'created_at': datetime.now().isoformat(),
            'successful_registrations': user_processes[username].get('successful', 0),
            'failed_registrations': user_processes[username].get('failed', 0),
            'success_rate': round(success_rate, 1),
            'total_domains_processed': total_processed,
            'email_used': email,
            'error': str(e)
        }
        
        save_user_process_data(username, process_data)

def run_subscription_process(username, email, domains):
    def run_async_in_thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(run_subscription_process_async(username, email, domains))
        finally:
            loop.close()
    
    thread = threading.Thread(target=run_async_in_thread, daemon=True)
    thread.start()
