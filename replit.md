# Overview

TSS Gmail Access is a Flask-based web application that provides secure, role-based access to multiple Gmail accounts through IMAP connections. The application features a comprehensive authentication system with entity-based access control, allowing different TSS entities (TSS1, TSS2, TSS3, TSSW) to access their designated Gmail accounts. Users can log in with their credentials and view email data through a clean, responsive dashboard interface.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Web Framework Architecture
The application uses Flask as the core web framework with Flask-Login for authentication and a secure MVC pattern:
- **app.py**: Main application logic with authentication, IMAP connection handling, and email processing
- **main.py**: Application entry point with development server configuration
- **templates/login.html**: Secure login interface with modern design
- **templates/dashboard.html**: Entity-specific dashboard using Jinja2 templating
- **users.txt**: User authentication database (entity, username, password)
- **gmailaccounts.txt**: Gmail account configuration (entity, email, app_password)

## Frontend Design
- **Responsive Design**: Built with Tailwind CSS for mobile-first responsive layout
- **Interactive Elements**: Custom CSS animations and hover effects for enhanced user experience
- **Icon Integration**: Font Awesome icons for visual consistency
- **Form Handling**: JavaScript-enhanced form submission for account selection

## Email Processing Architecture
- **Optimized IMAP Integration**: Direct connection to Gmail's IMAP servers using Python's imaplib with UID-based fetching
- **Performance Optimization**: Fetches only email headers (not full body) and limits to last 20 emails per folder maximum
- **Client-side Filtering**: Real-time search filtering performed in browser for instant results without server requests
- **MIME Decoding**: Custom functions for handling various email encodings and character sets
- **Error Handling**: Comprehensive logging and error management for connection failures

## Security Model
- **Flask-Login Authentication**: Secure session management with user login/logout functionality
- **Entity-Based Access Control**: Users can only access Gmail accounts from their assigned entity
- **TSSW Admin Access**: TSSW users have full access to all entity Gmail accounts
- **App Passwords**: Uses Gmail App Passwords instead of regular passwords for enhanced security
- **File-Based User Management**: Secure user authentication from users.txt file
- **Session Persistence**: Remember user login sessions until explicit logout
- **Environment Variables**: Session secrets with development fallback

## Data Flow
1. User logs in with username and password from users.txt
2. System authenticates and determines user's entity access level
3. Dashboard displays only Gmail accounts available to user's entity
4. User selects Gmail account from entity-filtered dropdown
5. Application establishes IMAP connection using stored credentials from gmailaccounts.txt
6. Email data is fetched and processed for display
7. Results are rendered through Flask templates with comprehensive error handling
8. User sessions persist until explicit logout

# External Dependencies

## Core Dependencies
- **Flask**: Web framework for routing and templating
- **Flask-Login**: Authentication and session management
- **imaplib**: Python standard library for IMAP email access
- **email**: Python standard library for email parsing and MIME handling

## Frontend Dependencies
- **Tailwind CSS**: Utility-first CSS framework loaded via CDN
- **Font Awesome**: Icon library for UI elements loaded via CDN

## Email Service Integration
- **Gmail IMAP**: Direct integration with Gmail's IMAP servers (imap.gmail.com:993)
- **App Passwords**: Requires Gmail App Password authentication for each account

## Development Environment
- **Python Logging**: Built-in logging for debugging and error tracking
- **Flask Development Server**: Hot reloading enabled for development

## Hosting Requirements
- **Port Configuration**: Configured to run on port 5000 with host binding to 0.0.0.0
- **Environment Variables**: Supports SESSION_SECRET environment variable for production security
- **File Permissions**: Requires read access to users.txt and gmailaccounts.txt files

# Entity Access Control System

## User Entities
- **TSS1**: Access to TSS1-specific Gmail accounts only
- **TSS2**: Access to TSS2-specific Gmail accounts only  
- **TSS3**: Access to TSS3-specific Gmail accounts only
- **TSSF**: Access to TSSF-specific Gmail accounts only (Finance entity)
- **TSSW**: Administrative access to all entity Gmail accounts (TSS1, TSS2, TSS3, TSSF, plus TSSW-specific accounts)

## Entity Color Coding
Visual identification in Gmail account dropdown menu:
- **TSS1**: Blue (bg-gradient-to-br from-blue-500 to-blue-600)
- **TSS2**: Green (bg-gradient-to-br from-green-500 to-green-600)
- **TSS3**: Yellow (bg-gradient-to-br from-yellow-500 to-yellow-600)
- **TSSF**: Orange (bg-gradient-to-br from-orange-500 to-orange-600)
- **TSSW**: Red (bg-gradient-to-br from-red-500 to-red-600)

## Authentication Files
- **users.txt**: Format: `Entity,Name,Username,Password[,permissions]` (one per line)
  - Permissions can include: 
    - `ok` (toggle permissions)
    - `allow_add_gmail_of_news` (manage news accounts)
    - `Domain_checker` (access Domain Checker service)
    - `find_news` (access Find News service)
    - `Extract_emails` (access Extract Emails service)
    - `tssw_report` (access TSSW Rapport service)
  - Multiple permissions separated by comma
- **gmailaccounts.txt**: Format: `Entity,EmailAddress,AppPassword[,news]` (one per line)
  - Add `,news` suffix to mark accounts for the "Find News" service

## Recent Changes (December 2025)

### Blacklist Lookup Service Optimization (December 19, 2025)
- ✅ Blacklist Lookup: Implemented parallel processing with ThreadPoolExecutor (30 concurrent workers)
- ✅ Blacklist Lookup: Added SSE streaming for real-time progress display (X/Y format with animated progress bar)
- ✅ Blacklist Lookup: Moved DQS_KEY to environment variable for security
- ✅ Blacklist Lookup: Complete UI redesign with modern glassmorphism design (purple/blue gradients)
- ✅ Blacklist Lookup: Added pagination with 16 items per page, prev/next buttons and page numbers
- ✅ Blacklist Lookup: Added search bar for filtering by server name, IP, or domain
- ✅ Blacklist Lookup: Moved Copy Clean IPs and Export CSV buttons to top toolbar
- ✅ Blacklist Lookup: Added column filters for all blacklist types (CSS, PBL, XBL, SBL, Barracuda, DBL)
- ✅ Blacklist Lookup: Responsive table with horizontal scrolling and clear button

### Domain Checker Enhancements and TSSW Rapport (December 13, 2025)
- ✅ Domain Checker: Added SPF A Records subdomain validation (requires 1 line for all domains OR exact count matching domains)
- ✅ Domain Checker: Created unified Domain Lookup tab merging MX/TXT tabs with checkboxes for MX, TXT, SPF, A Records
- ✅ Domain Lookup: Implemented SSE streaming with parallel processing (ThreadPoolExecutor, 20 concurrent queries)
- ✅ Domain Lookup: Fixed scrollable results table (400px height) with per-type filter dropdowns
- ✅ Domain Lookup: Added color-coded badges (green for Found, red for Not Found) and column visibility toggles
- ✅ Domain Lookup: Added quick stats summary and CSV export for filtered/visible results
- ✅ Domain Lookup: Added search by domain functionality
- ✅ New TSSW Rapport service with `tssw_report` permission check
- ✅ Created `/tssw_rapport` route and template with permission-gated access
- ✅ Added TSSW Rapport service card to services page (visible only with tssw_report permission)

### Performance and Permission Updates (December 8, 2025)
- ✅ Optimized login/logout by removing Gmail connection manager calls (faster authentication)
- ✅ Added new permissions: `find_news` and `Extract_emails` for service-level access control
- ✅ Services page now conditionally displays Find News and Extract Emails based on user permissions
- ✅ Route-level permission checks redirect unauthorized users to services page
- ✅ Domain Checker DMARC: Added filter dropdown (all/found/not_found), textarea with copy button, optional prefix input
- ✅ Domain Checker SPF: Dual input system for domains and prefixed domains (line-by-line matching)
- ✅ Domain Checker MX/TXT: Added filter dropdowns and copy button for filtered domains
- ✅ Find News: Fixed clipboard copy with fallback method for hosted environments
- ✅ Added toast-style auto-dismiss notifications positioned on right side

### User Profile and Permission System (December 4, 2025)
- ✅ Updated users.txt format to include Name field: `entity,Name,username,password[,permissions]`
- ✅ Personalized user experience now displays Name in welcome messages and navigation bars
- ✅ Added permission system supporting multiple permissions per user (ok, allow_add_gmail_of_news)
- ✅ Moved "Find News" service to services page for easier access and organization
- ✅ Implemented full Gmail account management for "Find News" service (add/edit/delete)
- ✅ Permission-based account management: TSSW users can manage all entities, others limited to their own
- ✅ Enhanced security with entity-scoped authorization for account modifications

## Recent Changes (August 2025)
### Multi-Service Platform Implementation (August 26, 2025)
- ✅ Transformed application into multi-service platform with service selection dashboard
- ✅ Added "TSS Gmail Access" service (existing functionality)
- ✅ Implemented "TSS Extract Emails" service with advanced email analysis
- ✅ Email extraction features: SPF/DKIM status, sender IP addresses, email categorization
- ✅ Added filtering by domain and subject with case-insensitive matching
- ✅ Implemented CSV export functionality for extracted data
- ✅ Ensured emails remain unread during extraction process
- ✅ Available to all entities with any Gmail credentials (not entity-restricted)

### TSSF Entity Integration and Color Coding System (August 26, 2025)
- ✅ Added new TSSF entity (Finance) with same access control as TSS1/TSS2/TSS3
- ✅ Updated TSSW access to include TSSF accounts alongside TSS1/TSS2/TSS3
- ✅ Implemented entity-based color coding system in Gmail account dropdown
- ✅ Added example TSSF Gmail accounts and users to configuration files
- ✅ Enhanced visual identification with gradient color scheme

### Migration to Replit Environment  
- ✅ Successfully migrated from Replit Agent to standard Replit environment
- ✅ Installed all required dependencies (Flask, Flask-Login, gunicorn, etc.)
- ✅ Configured proper port binding and server settings
- ✅ Created PostgreSQL database for future expansion

### Enhanced Entity-Based Connection System (August 17, 2025)
- ✅ Implemented entity-based connection pooling - when one user from an entity logs in, ALL Gmail accounts for that entity connect automatically
- ✅ Added smart connection management - connections only exist when entity has active users
- ✅ Enhanced TSSW admin functionality - TSSW users trigger connections to ALL entities
- ✅ Optimized for multiple concurrent users per entity sharing the same Gmail connections
- ✅ Eliminated per-user connection overhead - connections are now shared at entity level
- ✅ Improved real-time email updates with entity-based monitoring threads
- ✅ Added automatic cleanup when last user from entity logs out

### Real-time Email System Implementation
- ✅ Implemented advanced connection pooling system for efficient IMAP connections
- ✅ Added persistent Gmail connections shared among multiple users
- ✅ Created Server-Sent Events (SSE) for real-time email updates in browser
- ✅ Implemented automatic connection management (connects when users join, disconnects when no users)
- ✅ Added reliable polling system (every 10 seconds) replacing problematic IDLE implementation
- ✅ Fixed Gmail folder categorization using cached category searches
- ✅ Enhanced email fetching to get 50 most recent emails from Inbox and Spam folders
- ✅ Improved error handling and automatic reconnection for dropped connections
- ✅ Optimized performance to handle 10+ concurrent users efficiently

### Previous Features (January 2025)
- ✅ Implemented Flask-Login authentication system
- ✅ Added entity-based access control for Gmail accounts
- ✅ Created secure login interface with modern design
- ✅ Developed entity-specific dashboard with user info display
- ✅ Added persistent session management with remember me functionality
- ✅ Implemented file-based user and Gmail account management
- ✅ Added TSSW administrative access to all entities
- ✅ Enhanced security with proper logout functionality
- ✅ Added Gmail folder categorization (Primary, Promotions, Social, Updates, Forums, Spam)
- ✅ Created color-coded folder badges for visual distinction
- ✅ Added folder type filtering with dropdown selection
- ✅ Enhanced client-side filtering for instant search results
- ✅ Created responsive table layout with separate columns for better readability
- ✅ Enhanced mobile responsiveness with adaptive column display