import os
import json
import random
import re
import time
import requests
from playwright.sync_api import sync_playwright

# ================= CONFIG =================

IMAGES_DIR = "images"
KEYWORDS_FILE = "keywords.txt"
SUBJECT_FILE = "subject.txt"
IMAGE_LINK_FILE = "image_links.txt"

MIN_IMAGE_SIZE = 60 * 1024        # 60 KB
MAX_IMAGE_SIZE = 200 * 1024       # 200 KB
SKIP_EXTENSIONS = [".webp"]

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/132.0.0.0 Safari/537.36"
)

os.makedirs(IMAGES_DIR, exist_ok=True)

# =========================================
# ASK USER HOW MANY IMAGES
# =========================================

try:
    TOTAL_IMAGES = int(input("How many images do you want? ").strip())
    if TOTAL_IMAGES <= 0:
        raise ValueError
except:
    print("Invalid number. Defaulting to 1 image.")
    TOTAL_IMAGES = 1

# =========================================
# SUBJECT GENERATION (MEANINGFUL)
# =========================================

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

def generate_subject():
    return random.choice(SUBJECT_TEMPLATES).format(
        service=random.choice(SERVICE_PHRASES)
    )

def clean_filename(text):
    text = re.sub(r"[^\w\s-]", "", text)
    return text.replace(" ", "_")

# =========================================
# LOAD + RANDOMIZE KEYWORDS
# =========================================

with open(KEYWORDS_FILE, "r", encoding="utf-8") as f:
    all_keywords = [k.strip() for k in f if k.strip()]

if len(all_keywords) < TOTAL_IMAGES:
    raise ValueError("Not enough keywords in keywords.txt")

selected_keywords = random.sample(all_keywords, TOTAL_IMAGES)

print(f"\nSelected keywords: {selected_keywords}")

subjects = []
image_names = []

# =========================================
# PLAYWRIGHT (HEADLESS)
# =========================================

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(user_agent=UA)
    page = context.new_page()

    for keyword in selected_keywords:
        print(f"\nSearching: {keyword}")

        page.goto(
            f"https://www.bing.com/images/search?q={keyword}&form=HDRSC2",
            wait_until="domcontentloaded",
            timeout=60000,
        )

        page.wait_for_selector("a.iusc", timeout=15000)
        results = page.query_selector_all("a.iusc")
        random.shuffle(results)

        for item in results:
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

            ext = os.path.splitext(img_url.split("?")[0])[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            try:
                r = requests.get(
                    img_url,
                    headers={
                        "User-Agent": UA,
                        "Referer": "https://www.bing.com/",
                    },
                    timeout=20,
                )

                ct = r.headers.get("Content-Type", "").lower()
                size = len(r.content)

                if (
                    not r.ok
                    or "image" not in ct
                    or size < MIN_IMAGE_SIZE
                    or size > MAX_IMAGE_SIZE
                ):
                    print(f"    skipped (size {size // 1024} KB)")
                    continue

                if "webp" in ct:
                    continue

                ext = ".png" if "png" in ct else ".jpg"

                subject = generate_subject()
                filename = f"{clean_filename(subject)}{ext}"
                path = os.path.join(IMAGES_DIR, filename)

                with open(path, "wb") as f:
                    f.write(r.content)

                subjects.append(subject)
                image_names.append(filename)

                print(f"SAVED → {filename} ({size // 1024} KB)")
                break  # ✅ exactly ONE image per keyword

            except Exception as e:
                print("Download failed:", e)

        time.sleep(1)

    browser.close()

# =========================================
# SAVE OUTPUT FILES
# =========================================

with open(SUBJECT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(subjects))

with open(IMAGE_LINK_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(image_names))

print(f"\nDone — {len(image_names)} images saved TOTAL.")
