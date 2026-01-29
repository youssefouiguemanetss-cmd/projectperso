import os
import time
import random
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

PDF_DIR = "pdfs"
os.makedirs(PDF_DIR, exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

MAX_PDFS = int(input("How many PDFs do you want? "))
MAX_FILE_SIZE = 5 * 1024 * 1024
downloaded = 0


PDF_LINKS_FILE = "pdf_links.txt"
SUBJECT_FILE = "subject.txt"

try:
    with open("keywords.txt", "r", encoding="utf-8") as f:
        all_keywords = [line.strip() for line in f if line.strip()]
    
    if not all_keywords:
        print("❌ Error: keywords.txt is empty. Please add some keywords.")
        exit()
        
    print(f"📚 Loaded {len(all_keywords)} keywords from keywords.txt")
    
except FileNotFoundError:
    print("❌ Error: keywords.txt file not found. Please create it with one keyword per line.")
    exit()


available_keywords = all_keywords.copy()

used_keywords = set()
seen = set()
downloaded_per_keyword = {}
attempt_count = 0
max_attempts = MAX_PDFS * 3

downloaded_pdfs = []
downloaded_subjects = []

print(f"\n🎯 Target: {MAX_PDFS} PDFs (max 5 MB each)")
print("🔍 Looking for PDFs with names containing no numbers and 5+ words")

def is_good_filename(filename):
    """
    Check if a filename meets our criteria:
    1. Has no numbers in the name (before .pdf)
    2. Has at least 5 words separated by underscores
    """

    name_without_ext = filename.replace('.pdf', '')
    

    if any(char.isdigit() for char in name_without_ext):
        return False
    

    words = [w for w in name_without_ext.split('_') if w.strip()]
    

    if len(words) >= 5:
        return True
    
    return False

def extract_paper_title(abs_soup):
    """Extract paper title from abstract page"""
    try:
        
        title_selectors = [
            "h1.title",
            "h1.mathjax",
            ".title.mathjax",
            "h1",
            ".title"
        ]
        
        for selector in title_selectors:
            title_element = abs_soup.select_one(selector)
            if title_element:
                
                title = title_element.get_text(strip=True)
               
                if title.lower().startswith('title:'):
                    title = title[6:].strip()
                return title[:100]
    except:
        pass
    return None

def save_pdf_info():
    """Save PDF information to text files"""
    try:
        
        with open(PDF_LINKS_FILE, "w", encoding="utf-8") as f:
            for pdf_name in downloaded_pdfs:
                f.write(f"{pdf_name}\n")
        print(f"💾 Saved {len(downloaded_pdfs)} PDF names to '{PDF_LINKS_FILE}'")
        
        
        with open(SUBJECT_FILE, "w", encoding="utf-8") as f:
            for subject in downloaded_subjects:
                f.write(f"{subject}\n")
        print(f"💾 Saved {len(downloaded_subjects)} subjects to '{SUBJECT_FILE}'")
        
    except Exception as e:
        print(f"⚠ Warning: Could not save PDF information: {e}")

while downloaded < MAX_PDFS and attempt_count < max_attempts:
    attempt_count += 1
    
   
    if not available_keywords:
       
        available_keywords = [k for k in all_keywords if k not in used_keywords or downloaded_per_keyword.get(k, 0) == 0]
        
        if not available_keywords:
           
            available_keywords = all_keywords.copy()
    
   
    keyword = random.choice(available_keywords)
    available_keywords.remove(keyword)
    used_keywords.add(keyword)
    

    if keyword not in downloaded_per_keyword:
        downloaded_per_keyword[keyword] = 0
    
    
    encoded_keyword = requests.utils.quote(keyword)
    search_url = f"https://arxiv.org/search/?query={encoded_keyword}&searchtype=all&source=header"
    
    print(f"\n[{downloaded+1}/{MAX_PDFS}] 🔍 Trying keyword: '{keyword}'")
    
    try:
        r = requests.get(search_url, headers=HEADERS, timeout=20)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"  ❌ Failed to access search page: {e}")
        continue
        
    soup = BeautifulSoup(r.text, "html.parser")

   
    paper_links = soup.select("p.list-title.is-inline-block a[href^='/abs/']")
    
    if not paper_links:
        
        paper_links = soup.select("a[href*='/abs/']")
    
    if not paper_links:
        print(f"  ⚠ No papers found for '{keyword}'. Trying another keyword...")
        continue
    
    print(f"  Found {len(paper_links)} papers")
    
   
    pdf_downloaded = False
    papers_tried = 0
    
    for link in paper_links:
        if downloaded >= MAX_PDFS:
            break
        
        if pdf_downloaded:
            
            break
        
        papers_tried += 1
        if papers_tried > 10: 
            break

        abs_url = urljoin("https://arxiv.org", link["href"])
        if abs_url in seen:
            continue
        seen.add(abs_url)

        print(f"  ➜ Visiting paper {papers_tried}")

        try:
            abs_page = requests.get(abs_url, headers=HEADERS, timeout=20)
            abs_page.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"    ❌ Failed to access abstract page: {e}")
            continue
            
        abs_soup = BeautifulSoup(abs_page.text, "html.parser")
        
        
        paper_title = extract_paper_title(abs_soup)

        
        pdf_selectors = [
            "a[href$='.pdf']",
            "a:-soup-contains('PDF')",  
            "a[href*='/pdf/']",
            "a[href*='download']"
        ]
        
        pdf_link = None
        for selector in pdf_selectors:
            pdf_link = abs_soup.select_one(selector)
            if pdf_link and 'href' in pdf_link.attrs:
                break
        
        if not pdf_link:
      
            arxiv_id = abs_url.split('/')[-1]
            pdf_url = f"https://arxiv.org/pdf/{arxiv_id}.pdf"
        else:
            pdf_url = urljoin("https://arxiv.org", pdf_link["href"])
        
        
        if not pdf_url.endswith('.pdf'):
            pdf_url += '.pdf'
        
      
        original_filename = os.path.basename(pdf_url)
       
        original_filename = original_filename.split('?')[0]
        if not original_filename.endswith('.pdf'):
            original_filename += '.pdf'
        
       
        if paper_title:
            
            clean_title = re.sub(r'[^a-zA-Z\s]', ' ', paper_title)
            
            clean_title = re.sub(r'\s+', ' ', clean_title).strip()
            
            words = clean_title.split()
            if len(words) >= 5:  
                
                filename_parts = []
                for word in words:
                   
                    filename_parts.append(word.capitalize())
                
                filename = '_'.join(filename_parts) + '.pdf'
                
               
                if not any(char.isdigit() for char in filename.replace('.pdf', '')):
                    print(f"    ✨ Good filename found: {filename}")
                else:
                    print(f"    ⚠ Skipping - Filename contains numbers: {filename}")
                    continue
            else:
                print(f"    ⚠ Skipping - Title too short: only {len(words)} words")
                continue
        else:
            print(f"    ⚠ Skipping - Could not extract paper title")
            continue
        
        filepath = os.path.join(PDF_DIR, filename)
        
       
        if os.path.exists(filepath):
            print(f"    ⏭ Already downloaded: {filename}")
            continue

        print(f"    ⬇ Downloading PDF...")
        
        try:
            with requests.get(pdf_url, headers=HEADERS, stream=True, timeout=30) as r:
                r.raise_for_status()
                
               
                content_length = r.headers.get('content-length')
                if content_length:
                    file_size = int(content_length)
                    if file_size > MAX_FILE_SIZE:
                        print(f"    ⚠ Skipping - File too large: {file_size / (1024*1024):.2f} MB")
                        continue
                
            
                content_type = r.headers.get('content-type', '')
                if 'application/pdf' not in content_type and 'pdf' not in content_type.lower():
                    print(f"    ❌ Not a PDF file: {content_type}")
                    continue
                
              
                downloaded_bytes = 0
                with open(filepath, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_bytes += len(chunk)
                            
                           
                            if downloaded_bytes > MAX_FILE_SIZE:
                                print(f"    ⚠ Cancelled - File exceeded 5 MB limit")
                                f.close()
                                os.remove(filepath)
                                break
                    else:
                        
                        final_size = os.path.getsize(filepath)
                        if final_size > MAX_FILE_SIZE:
                            print(f"    ⚠ Deleted - Final size exceeded 5 MB: {final_size / (1024*1024):.2f} MB")
                            os.remove(filepath)
                            continue
                        
                        downloaded += 1
                        downloaded_per_keyword[keyword] += 1
                        pdf_downloaded = True
                        
                        
                        downloaded_pdfs.append(filename)
                        
                       
                        subject = filename.replace('.pdf', '').replace('_', ' ')
                        downloaded_subjects.append(subject)
                        
                       
                        words_in_name = len(filename.replace('.pdf', '').split('_'))
                        print(f"    ✅ Saved {filename} ({words_in_name} words, {final_size / (1024*1024):.2f} MB) ({downloaded}/{MAX_PDFS})")
                        break
                
               
                continue
                
        except requests.exceptions.RequestException as e:
            print(f"    ❌ Download failed: {e}")
            if os.path.exists(filepath):
                os.remove(filepath)
            continue
            
        time.sleep(0.5)
    
    if not pdf_downloaded:
        print(f"  ⚠ Could not find suitable PDF for '{keyword}'. Trying another keyword...")


save_pdf_info()


if downloaded < MAX_PDFS:
    print(f"\n⚠ Warning: Only downloaded {downloaded} out of {MAX_PDFS} requested PDFs.")
    print("  Possible reasons:")
    print("  1. Could not find PDFs with suitable filenames (5+ words, no numbers)")
    print("  2. Most papers are larger than 5 MB")
    print("  3. Keywords are too specific")
    print("  4. arXiv might be rate limiting")
else:
    print(f"\n🎉 Success! Downloaded all {MAX_PDFS} requested PDFs.")

print(f"\n📊 Summary by keyword:")
successful_keywords = 0
total_size = 0
for keyword, count in downloaded_per_keyword.items():
    if count > 0:
        print(f"  - {keyword}: {count} PDF(s)")
        successful_keywords += 1

if successful_keywords == 0:
    print("  No PDFs were downloaded.")

print(f"\n📁 Downloaded files ({downloaded} total, max 5 MB each, 5+ words, no numbers):")
pdf_files = [f for f in os.listdir(PDF_DIR) if f.endswith('.pdf')]
if pdf_files:
    print("┌" + "─" * 80 + "┐")
    for file in sorted(pdf_files):
        filepath = os.path.join(PDF_DIR, file)
        file_size = os.path.getsize(filepath)
        total_size += file_size
        size_mb = file_size / (1024*1024)
        word_count = len(file.replace('.pdf', '').split('_'))
        print(f"│ {file:<60} {word_count:>3} words {size_mb:>6.2f} MB │")
    
    avg_size = total_size / len(pdf_files) / (1024*1024)
    max_size = max(os.path.getsize(os.path.join(PDF_DIR, f)) for f in pdf_files) / (1024*1024)
    avg_words = sum(len(f.replace('.pdf', '').split('_')) for f in pdf_files) / len(pdf_files)
    
    print("├" + "─" * 80 + "┤")
    print(f"│ {'Total size:':<30} {total_size / (1024*1024):>45.2f} MB │")
    print(f"│ {'Average PDF size:':<30} {avg_size:>45.2f} MB │")
    print(f"│ {'Average words in filename:':<30} {avg_words:>45.1f} │")
    print(f"│ {'Largest PDF:':<30} {max_size:>45.2f} MB │")
    print("└" + "─" * 80 + "┘")
else:
    print("  No PDF files found in the folder.")


print(f"\n📄 Preview of generated files:")
print(f"\n📋 '{PDF_LINKS_FILE}' (first 5 entries):")
try:
    with open(PDF_LINKS_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[:5]
        for i, line in enumerate(lines, 1):
            print(f"  {i}. {line.strip()}")
    if len(downloaded_pdfs) > 5:
        print(f"  ... and {len(downloaded_pdfs) - 5} more")
except:
    print("  Could not read file")

print(f"\n📝 '{SUBJECT_FILE}' (first 5 entries):")
try:
    with open(SUBJECT_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[:5]
        for i, line in enumerate(lines, 1):
            print(f"  {i}. {line.strip()}")
    if len(downloaded_subjects) > 5:
        print(f"  ... and {len(downloaded_subjects) - 5} more")
except:
    print("  Could not read file")