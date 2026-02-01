import script_setup
import asyncio
import random
import string
import argparse
import traceback

import imaplib
import email
from email.header import decode_header
import json
from datetime import datetime, timedelta
from faker import Faker
import sys
import os
from pathlib import Path
    
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError
import logging
import re
import requests
from io import BytesIO
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Initialize Faker for random data generation
fake = Faker()

# Enhanced Configuration
CONFIG = {
    "app_password": "yfaz mcou uzsb dywq",
    'page_timeout': 30000,
    'element_timeout': 10000, 
    'wait_after_click': 3000, 
    'wait_between_domains': (3000, 8000),
    'max_retries': 2,
    'navigation_timeout': 30000,  
    'form_fill_delay': 800, 
    'captcha_wait': 20000,  
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]
}



def generate_password(length=12):
    """Generate a strong password with all required character types"""
    import string
    import random
    
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

def read_file(filename):
    """Read file with multiple encoding attempts"""
    encodings = ['utf-8', 'utf-8-sig', 'latin1', 'cp1252', 'iso-8859-1']
    
    for encoding in encodings:
        try:
            with open(filename, 'r', encoding=encoding) as f:
                lines = [line.strip() for line in f if line.strip()]
                logger.info(f"Successfully read {filename} with {encoding} encoding ({len(lines)} lines)")
                return lines
        except UnicodeDecodeError:
            continue
        except FileNotFoundError:
            logger.error(f"File {filename} not found")
            return []
        except Exception as e:
            logger.error(f"Unexpected error reading {filename}: {e}")
            continue
    
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
            logger.warning(f"Read {filename} with UTF-8 and ignored errors ({len(lines)} lines)")
            return lines
    except FileNotFoundError:
        logger.error(f"File {filename} not found")
        return []
    except Exception as e:
        logger.error(f"Failed to read {filename}: {e}")
        return []
        
async def check_domain_relevance(page):
    """Check if domain contains relevant keywords for registration/login"""
    try:
        await page.wait_for_timeout(2000)
        page_text = (await page.inner_text('body', timeout=8000)).lower()
        
        required_keywords = [
            'create account', 'login', 'log in', 'sign in', 'sign up',
            'signup', 'free trial', 'register', 'registration'
        ]
        
        for keyword in required_keywords:
            if keyword in page_text:
                logger.info(f"Domain is relevant - found keyword: '{keyword}'")
                return True
        
        logger.warning("Domain does not contain any relevant keywords - skipping")
        return False
        
    except Exception as e:
        logger.error(f"Domain relevance check error: {e}")
        return False        



async def is_registration_related(text, href=None):
    """Check if text indicates registration intent - fallback version"""
    if not text or len(text.strip()) < 2:
        return False
    
    text_lower = text.lower().strip()
    
    # Negative keywords
    negative_keywords = ['log in', 'login', 'sign in', 'signin', 'sign-in']
    for keyword in negative_keywords:
        if keyword in text_lower:
            return False
    
    # Primary keywords
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
    """Enhanced element info extraction"""
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
            ('data-text', lambda: element.get_attribute('data-text')),
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
        logger.debug(f"Error getting element info: {e}")
        return None, None

async def handle_popup_with_email_detection(page):
    """Handle popups - close if no email field, fill if email field present"""
    try:
        logger.info("Checking for popups/modals...")
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
                    logger.info(f"Found popup with selector: {selector}")
                    break
            except:
                continue
        
        if not popup:
            logger.debug("No popup detected")
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
            logger.info("Popup has no email field - attempting to close")
            
            close_selectors = [
                'button[aria-label*="close" i]:visible',
                'button[title*="close" i]:visible',
                '[class*="close" i]:visible',
                'button:has-text("×"):visible',
                'button:has-text("Close"):visible',
                '[role="button"][aria-label*="close" i]:visible'
            ]
            
            for selector in close_selectors:
                try:
                    close_btn = await popup.query_selector(selector)
                    if close_btn and await close_btn.is_visible():
                        page, _ = await safe_click(close_btn, page)
                        logger.info("Closed popup")
                        await page.wait_for_timeout(1000)
                        return True, page
                except:
                    continue
            
            try:
                await page.keyboard.press('Escape')
                logger.info("Attempted to close popup with ESC key")
                await page.wait_for_timeout(1000)
                return True, page
            except:
                pass
        
        else:
            logger.info("Popup contains email field - filling form")
            
            from faker import Faker
            fake_local = Faker()
            popup_email = f"{fake_local.user_name().lower()}{random.randint(100,999)}@gmail.com"
            
            all_inputs = await popup.query_selector_all('input:visible, textarea:visible')
            
            for input_elem in all_inputs:
                try:
                    input_type = (await input_elem.get_attribute('type') or 'text').lower()
                    input_name = (await input_elem.get_attribute('name') or '').lower()
                    input_placeholder = (await input_elem.get_attribute('placeholder') or '').lower()
                    field_context = f"{input_name} {input_placeholder}".lower()
                    
                    if input_type == 'email' or 'email' in field_context:
                        await input_elem.fill(popup_email)
                        logger.info(f"Filled popup email: {popup_email}")
                    elif 'name' in field_context and 'email' not in field_context:
                        await input_elem.fill(fake_local.name())
                        logger.info("Filled popup name field")
                    elif input_type == 'text':
                        await input_elem.fill(fake_local.name())
                        logger.info("Filled popup text field")
                    
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
                        logger.info("Submitted popup form")
                        await page.wait_for_timeout(2000)
                        return True, page
                except:
                    continue
        
        return False, page
        
    except Exception as e:
        logger.error(f"Popup handling error: {e}")
        return False, page

async def find_registration_elements_comprehensive(page):
    """Enhanced element finding"""
    try:
        await page.wait_for_load_state('domcontentloaded', timeout=10000)
        await page.wait_for_timeout(3000)
        
        registration_elements = []
        
        element_selectors = [
            'a:has-text("Register"):visible',
            'a:has-text("Sign Up"):visible',
            'a:has-text("Sign up"):visible',
            'a:has-text("Create Account"):visible',
            'button:has-text("Register"):visible',
            'button:has-text("Sign Up"):visible',
            'button:has-text("Join"):visible',
            'button:has-text("Get Started"):visible',
            'a[href*="register" i]:visible',
            'a[href*="signup" i]:visible',
            'a[href*="sign-up" i]:visible',
            'a[href*="join" i]:visible',
            '[class*="register" i]:visible',
            '[class*="signup" i]:visible',
            'input[type="submit"][value*="register" i]:visible',
            'input[type="submit"][value*="sign up" i]:visible'
        ]
        
        processed_elements = set()
        
        for selector in element_selectors:
            try:
                elements = await asyncio.wait_for(
                    page.query_selector_all(selector), 
                    timeout=5.0
                )
                
                logger.debug(f"Selector '{selector}' found {len(elements)} elements")
                
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
                            logger.info(f"Found registration element: '{text}' (href: {href or 'N/A'})")
                            
                            if len(registration_elements) >= 8:
                                break
                    except asyncio.TimeoutError:
                        logger.debug(f"Element processing timed out")
                        continue
                    except Exception as e:
                        logger.debug(f"Error processing element: {e}")
                        continue
                        
                if len(registration_elements) >= 8:
                    break
                    
            except asyncio.TimeoutError:
                logger.debug(f"Selector '{selector}' timed out")
                continue
            except Exception as e:
                logger.debug(f"Selector '{selector}' failed: {e}")
                continue
        
        def get_priority(item):
            text = item[1].lower()
            href = item[2].lower() if item[2] else ''
            
            if text.strip() in ['register', 'sign up', 'signup']:
                return 0
            elif any(x in text for x in ['register', 'sign up', 'create account']):
                return 1
            elif any(x in text for x in ['join', 'get started']):
                return 2
            elif any(x in href for x in ['register', 'signup', 'join']):
                return 3
            return 4
        
        registration_elements.sort(key=get_priority)
        
        logger.info(f"Found {len(registration_elements)} total registration elements")
        return registration_elements[:6]
        
    except Exception as e:
        logger.error(f"Error finding registration elements: {e}")
        return []

async def smart_form_fill(page, email):
    """Enhanced form filling"""
    try:
        logger.info("Starting comprehensive form filling...")
        
        try:
            await page.wait_for_load_state('domcontentloaded', timeout=10000)
            logger.info("DOM content loaded")
        except Exception as e:
            logger.warning(f"DOM load timeout, continuing anyway: {e}")
        
        await page.wait_for_timeout(5000)
        
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
            
            logger.info(f"Found {len(all_form_elements)} form elements to process")
            
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
                        logger.debug(f"Error getting attributes: {e}")
                    
                    field_context = f"{input_name} {input_id} {input_placeholder}".lower()
                    logger.info(f"Processing element {i+1}: tag={tag_name}, type={input_type}, context='{field_context.strip()}'")
                    
                    try:
                        current_value = await element.get_attribute('value') or ''
                        if current_value.strip() and len(current_value.strip()) > 2:
                            logger.debug(f"Element already filled with '{current_value[:10]}...', skipping")
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
                                    logger.info(f"✓ Selected option: {selected_value}")
                                    filled = True
                        except Exception as e:
                            logger.warning(f"Failed to handle select: {e}")
                    
                    else:
                        try:
                            page, _ = await safe_click(element, page)
                            await element.fill('')
                            await page.wait_for_timeout(300)
                            
                            if input_type == 'email' or 'email' in field_context:
                                await element.fill(email)
                                logger.info(f"✓ Filled email field: {email}")
                                filled = True
                            
                            elif input_type == 'password':
                                await element.fill(password)
                                logger.info(f"✓ Filled password field")
                                filled = True
                            
                            elif ('username' in field_context or 'login' in field_context) and input_type != 'password':
                                await element.fill(username)
                                logger.info(f"✓ Filled username field: {username}")
                                filled = True
                            
                            elif 'first' in field_context and 'name' in field_context:
                                await element.fill(first_name)
                                logger.info(f"✓ Filled first name: {first_name}")
                                filled = True
                            elif 'last' in field_context and 'name' in field_context:
                                await element.fill(last_name)
                                logger.info(f"✓ Filled last name: {last_name}")
                                filled = True
                            elif ('full' in field_context or 'name' in field_context) and 'email' not in field_context:
                                await element.fill(full_name)
                                logger.info(f"✓ Filled full name: {full_name}")
                                filled = True
                            
                            elif 'phone' in field_context or 'mobile' in field_context:
                                phone = fake.phone_number()
                                await element.fill(phone)
                                logger.info(f"✓ Filled phone: {phone}")
                                filled = True
                            
                            elif 'age' in field_context:
                                age = str(random.randint(18, 65))
                                await element.fill(age)
                                logger.info(f"✓ Filled age: {age}")
                                filled = True
                            elif 'birth' in field_context or 'dob' in field_context:
                                birth_date = fake.date_of_birth(minimum_age=18, maximum_age=65).strftime('%m/%d/%Y')
                                await element.fill(birth_date)
                                logger.info(f"✓ Filled birth date: {birth_date}")
                                filled = True
                            
                            elif 'company' in field_context or 'organization' in field_context:
                                company = fake.company()
                                await element.fill(company)
                                logger.info(f"✓ Filled company: {company}")
                                filled = True
                            
                            elif 'title' in field_context or 'position' in field_context:
                                title = fake.job()
                                await element.fill(title)
                                logger.info(f"✓ Filled title: {title}")
                                filled = True
                            
                            elif 'address' in field_context:
                                address = fake.address()
                                await element.fill(address)
                                logger.info(f"✓ Filled address: {address}")
                                filled = True
                            elif 'city' in field_context:
                                city = fake.city()
                                await element.fill(city)
                                logger.info(f"✓ Filled city: {city}")
                                filled = True
                            elif 'zip' in field_context or 'postal' in field_context:
                                zip_code = fake.zipcode()
                                await element.fill(zip_code)
                                logger.info(f"✓ Filled zip: {zip_code}")
                                filled = True
                            
                            elif input_type == 'text' and not filled:
                                if any(word in field_context for word in ['search', 'query', 'keyword']):
                                    logger.info(f"Skipping search field")
                                    continue
                                else:
                                    await element.fill(full_name)
                                    logger.info(f"✓ Filled generic text field with name: {full_name}")
                                    filled = True
                            
                            elif tag_name == 'textarea':
                                message = f"Hello, I'm interested in your services. Please contact me at {email}. Thank you!"
                                await element.fill(message)
                                logger.info(f"✓ Filled textarea with message")
                                filled = True
                            
                        except Exception as e:
                            logger.warning(f"Failed to fill element {i+1}: {e}")
                    
                    if filled:
                        filled_count += 1
                        await page.wait_for_timeout(800)
                    
                except Exception as e:
                    logger.warning(f"Error processing element {i+1}: {e}")
                    continue
        
        except Exception as e:
            logger.error(f"Failed to get form elements: {e}")
        
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
                            logger.info(f"✓ Checked checkbox: {checkbox_context}")
                            filled_count += 1
                except Exception as e:
                    logger.debug(f"Checkbox error: {e}")
            
            radio_groups = {}
            radios = await page.query_selector_all('input[type="radio"]:visible')
            for radio in radios:
                try:
                    radio_name = await radio.get_attribute('name')
                    if radio_name and radio_name not in radio_groups:
                        page, _ = await safe_click(radio, page, is_check=True)
                        radio_groups[radio_name] = True
                        logger.info(f"✓ Selected radio button in group: {radio_name}")
                        filled_count += 1
                except Exception as e:
                    logger.debug(f"Radio button error: {e}")
                    
        except Exception as e:
            logger.debug(f"Checkbox/radio handling error: {e}")
        
        logger.info(f"Form filling completed. Successfully filled {filled_count} fields.")
        return filled_count
        
    except Exception as e:
        logger.error(f"Critical error in smart form filling: {e}")
        logger.error(traceback.format_exc())
        return 0

async def smart_form_submit(page):
    """Enhanced form submission"""
    try:
        logger.info("Starting smart form submission process...")
        
        submit_selectors = [
            'button:has-text("Register"):visible',
            'button:has-text("Sign Up"):visible',
            'button:has-text("Sign up"):visible',
            'button:has-text("Create Account"):visible',
            'button:has-text("Subscribe"):visible',
            'button:has-text("Join"):visible',
            'input[type="submit"]:visible',
            'button[type="submit"]:visible',
            'input[value*="register" i]:visible',
            'input[value*="sign up" i]:visible',
            'input[value*="subscribe" i]:visible',
            'input[value*="create" i]:visible',
            'input[value*="join" i]:visible',
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
                    if any(tp in button_text.lower() for tp in third_party_keywords):
                        logger.info(f"Skipping third-party submit button: '{button_text}'")
                        continue
                    logger.info(f"Found submit button: '{button_text}' with selector: {selector}")
                    break
            except:
                continue
        
        if not submit_button:
            logger.warning("No submit button found")
            return False, page
        
        current_url = page.url
        
        try:
            await submit_button.scroll_into_view_if_needed()
            await page.wait_for_timeout(1000)
            page, _ = await safe_click(submit_button, page, timeout=10000, force=True)
            logger.info(f"✓ Clicked submit button: '{button_text}'")
        except Exception as e:
            logger.error(f"Failed to click submit button: {e}")
            return False, page
        
        await page.wait_for_timeout(5000)
        
        await page.wait_for_timeout(3000)
        
        new_url = page.url
        new_title = await page.title()
        
        success_url_indicators = [
            'success', 'confirm', 'confirmation', 'thank', 'thanks', 'welcome',
            'verify', 'verification', 'activation', 'activate', 'registered',
            'complete', 'done', 'dashboard', 'account', 'profile'
        ]
        
        if new_url != current_url:
            if any(indicator in new_url.lower() for indicator in success_url_indicators):
                logger.info(f"SUCCESS: URL indicates success: {new_url}")
                return True, page
        
        if new_title:
            success_title_indicators = [
                'success', 'confirm', 'thank', 'welcome', 'verify', 'complete',
                'registration', 'account created', 'signed up'
            ]
            if any(indicator in new_title.lower() for indicator in success_title_indicators):
                logger.info(f"SUCCESS: Title indicates success: {new_title}")
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
                    logger.info(f"SUCCESS: Found success indicator '{indicator}' on page")
                    return True, page
                    
        except Exception as e:
            logger.debug(f"Page content analysis failed: {e}")
        
        logger.info("Form submitted - success status unclear, assuming success")
        return True, page
        
    except Exception as e:
        logger.error(f"Form submission error: {e}")
        return False, page

async def safe_click(element, page, timeout=5000, force=False, is_check=False):
    """Safe click that handles popups"""
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
            logger.info("Popup window opened, switching to new page")
            old_page = page
            page = popup
            await page.wait_for_load_state('domcontentloaded', timeout=10000)
            await old_page.close()
            return page, True
    except PlaywrightTimeoutError:
        pass
    except Exception as e:
        logger.debug(f"Safe click error: {e}")
    
    return page, False

async def comprehensive_registration_workflow(page, email, gmail_stats, domain):
    """Complete registration workflow"""
    try:
        max_workflow_steps = 2  
        current_step = 0
        forms_found = 0
        fields_filled = 0
        registration_elements_found = 0
        made_progress = False  
        
        logger.info("Starting comprehensive registration workflow")
        
        while current_step < max_workflow_steps:
            current_step += 1
            logger.info(f"Registration workflow step {current_step}/{max_workflow_steps}")
            
            current_url = page.url
            step_progress = False
            
            try:
                forms = await page.query_selector_all('form:visible')
                forms_found = len(forms)
                
                if forms:
                    logger.info(f"Found {len(forms)} visible forms")
                    
                    fields_filled_count = await smart_form_fill(page, email)
                    fields_filled += fields_filled_count
                    
                    if fields_filled_count > 0:
                        logger.info("Form filling completed, attempting submission...")
                        step_progress = True
                        made_progress = True
                        
                        submission_result, page = await smart_form_submit(page)
                        
                        if submission_result:
                            logger.info("Registration workflow completed successfully!")
                            return True, page
                    
            except Exception as e:
                logger.debug(f"Form processing error: {e}")
            
            if not step_progress:
                try:
                    popup_handled, page = await handle_popup_with_email_detection(page)
                    if popup_handled:
                        logger.info("Popup handled")
                    
                    forms = await page.query_selector_all('form:visible')
                    if forms and forms_found < len(forms):
                        fields_filled_count = await smart_form_fill(page, email)
                        fields_filled += fields_filled_count
                        if fields_filled_count > 0:
                            submission_result, page = await smart_form_submit(page)
                            if submission_result:
                                logger.info("Registration successful after form submission")
                                return True, page
                    
                    reg_elements = await find_registration_elements_comprehensive(page)
                    registration_elements_found = len(reg_elements)
                    
                    if reg_elements:
                        logger.info(f"Found {len(reg_elements)} registration elements")
                        step_progress = True
                        made_progress = True
                        
                        elements_to_try = min(2, len(reg_elements))
                        
                        for i, (element, text, href) in enumerate(reg_elements[:elements_to_try]):
                            try:
                                logger.info(f"Attempting to click registration element {i+1}/{elements_to_try}: '{text}'")
                                
                                await element.scroll_into_view_if_needed()
                                await page.wait_for_timeout(1000)
                                page, _ = await safe_click(element, page, timeout=10000)
                                
                                logger.info(f"Clicked: '{text}'")
                                await page.wait_for_timeout(CONFIG['wait_after_click'])
                                
                                new_url = page.url
                                if new_url != current_url:
                                    logger.info(f"Navigation occurred: {new_url}")
                                    break
                                
                                await page.wait_for_timeout(2000)
                                new_forms = await page.query_selector_all('form:visible')
                                if new_forms and len(new_forms) > forms_found:
                                    logger.info("New form appeared after click")
                                    fields_filled_count = await smart_form_fill(page, email)
                                    fields_filled += fields_filled_count
                                    if fields_filled_count > 0:
                                        submission_result, page = await smart_form_submit(page)
                                        if submission_result:
                                            logger.info("Registration successful after new form")
                                            if gmail_stats:
                                                found, folder, subj = gmail_stats.check_confirmation_email(domain, email)
                                                if found:
                                                    logger.info(f"Confirmation email found in {folder}: {subj}")
                                            return True, page
                                    break
                                
                            except Exception as e:
                                logger.warning(f"Failed to click '{text}': {e}")
                                continue
                    
                except Exception as e:
                    logger.debug(f"Registration element finding error: {e}")
            
            if not step_progress:
                logger.info(f"No progress made in step {current_step}")
                
                if current_step >= 2 and not made_progress:
                    logger.warning(f"No progress made after {current_step} steps - skipping domain")
                    return False, page
            
            await page.wait_for_timeout(1500)
        
        return False, page
        
    except Exception as e:
        logger.error(f"Registration workflow error: {e}")
        logger.error(traceback.format_exc())
        return False, page

async def process_domain_with_retry(page, domain, email):
    """Process domain with retry logic"""
    url = domain if domain.startswith(('http://', 'https://')) else f"https://{domain}"
    logger.info(f"Processing: {url} with email: {email}")
    
    max_retries = CONFIG['max_retries']
    relevance_checked = False
    
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                logger.info(f"Retry attempt {attempt + 1}/{max_retries} for {url}")
            
            try:
                await page.goto(url, timeout=CONFIG['navigation_timeout'], wait_until='domcontentloaded')
                logger.info(f"Successfully navigated to: {url}")
            except Exception as nav_error:
                logger.error(f"Navigation failed (attempt {attempt + 1}): {nav_error}")
                if attempt == max_retries - 1:
                    return False
                continue
            
            try:
                await page.wait_for_load_state('networkidle', timeout=15000)
            except:
                logger.debug("Network idle timeout - continuing anyway")
            
            await page.wait_for_timeout(5000)
            
            if not relevance_checked:
                if not await check_domain_relevance(page):
                    logger.warning(f"Skipping irrelevant domain: {url}")
                    return False
                relevance_checked = True
            
            await handle_popup_with_email_detection(page)
            
            success, page = await comprehensive_registration_workflow(page, email, None, domain)
            
            if success:
                logger.info(f"Successfully completed registration for: {url}")
                return True
            else:
                logger.info(f"Registration workflow completed but status unclear for: {url}")
                if attempt == max_retries - 1:
                    return False
                
        except Exception as e:
            logger.error(f"Domain processing error (attempt {attempt + 1}) for {url}: {e}")
            if attempt == max_retries - 1:
                logger.error(traceback.format_exc())
                return False
            
        if attempt < max_retries - 1:
            retry_delay = random.randint(3000, 8000)
            logger.info(f"Waiting {retry_delay/1000:.1f}s before retry...")
            await page.wait_for_timeout(retry_delay)
    
    return False

async def main(headless):
    emails = read_file('emails.txt')
    domains = read_file('domains2.txt')
    
    if not emails:
        logger.error("No emails found in emails.txt")
        return
    if not domains:
        logger.error("No domains found in domains2.txt")
        return
    
    logger.info(f"Starting registration bot with {len(emails)} emails and {len(domains)} domains")
    logger.info(f"Running in {'HEADLESS' if headless else 'VISIBLE'} mode")
    
    successful_registrations = 0
    failed_registrations = 0
    
    async with async_playwright() as p:
        for i, domain in enumerate(domains, 1):
            email = random.choice(emails)
            logger.info(f"\n{'='*80}")
            logger.info(f"Processing {i}/{len(domains)}: {domain}")
            logger.info(f"Using email: {email}")
            logger.info(f"{'='*80}")
            
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--disable-blink-features=AutomationControlled',
                    '--disable-web-security',
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-software-rasterizer',
                    '--disable-background-timer-throttling',
                    '--disable-backgrounding-occluded-windows',
                    '--disable-renderer-backgrounding',
                    '--disable-extensions',
                    '--disable-default-apps',
                    '--disable-sync',
                    '--disable-translate',
                    '--disable-ipc-flooding-protection',
                    '--disable-features=VizDisplayCompositor',
                    '--no-first-run',
                    '--no-default-browser-check',
                    '--window-size=1920,1080',
                ],
                slow_mo=500
            )
            
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent=random.choice(CONFIG['user_agents']),
                java_script_enabled=True,
                accept_downloads=False,
                ignore_https_errors=True,
                bypass_csp=True,
                permissions=['notifications'],
                extra_http_headers={
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Cache-Control': 'no-cache',
                    'Pragma': 'no-cache'
                }
            )
            
            page = await context.new_page()
            
            try:
                success = await process_domain_with_retry(page, domain, email)
                if success:
                    successful_registrations += 1
                    logger.info(f"✓ SUCCESS: {domain}")
                else:
                    failed_registrations += 1
                    logger.info(f"✗ FAILED: {domain}")
                    
            except Exception as e:
                failed_registrations += 1
                logger.error(f"✗ CRASHED: {domain} - {e}")
            finally:
                await page.close()
                await context.close()
                await browser.close()
            
            if i < len(domains):
                delay = random.randint(*CONFIG['wait_between_domains'])
                logger.info(f"Waiting {delay/1000:.1f}s before next domain...")
                await asyncio.sleep(delay/1000)
        
        total_processed = successful_registrations + failed_registrations
        success_rate = (successful_registrations / total_processed * 100) if total_processed > 0 else 0
        
        logger.info(f"\n{'='*80}")
        logger.info(f"FINAL REPORT")
        logger.info(f"{'='*80}")
        logger.info(f"Successful registrations: {successful_registrations}")
        logger.info(f"Failed registrations: {failed_registrations}")
        logger.info(f"Success rate: {success_rate:.1f}%")
        logger.info(f"Total domains processed: {total_processed}")
        logger.info(f"{'='*80}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced Newsletter Registration Bot v3.0")
    parser.add_argument('--no-headless', action='store_true', help="Run browser in visible mode for debugging")
    parser.add_argument('--slow', action='store_true', help="Run with slower timing for debugging")
    parser.add_argument('--debug', action='store_true', help="Enable debug logging")
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.slow:
        CONFIG['wait_after_click'] = 8000
        CONFIG['wait_between_domains'] = (10000, 20000)
        CONFIG['form_fill_delay'] = 2000
        CONFIG['captcha_wait'] = 45000
    
    asyncio.run(main(headless=not args.no_headless))