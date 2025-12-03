from urllib.parse import urlparse, urlunparse
import logging

def clean_git_url(url: str) -> str:
    """Clean and normalize git URLs for consistent processing."""
    logging.debug(f"Cleaning git URL: {url}")
    
    if not url:
        return url
        
    # Remove .git suffix
    if url.endswith('.git'):
        url = url[:-4]
    
    # Handle SSH URLs
    if url.startswith('git@'):
        url = url.split(':')[-1]
    
    if url.startswith('git+ssh://git@'):
        url = url.split('git@github.com/')[-1]
    
    # Parse and normalize
    parsed_url = urlparse(url)
    
    # Handle git+ scheme
    if parsed_url.scheme == 'git+':
        parsed_url = parsed_url._replace(scheme='https')
    
    # Remove www prefix
    if parsed_url.netloc.startswith('www.'):
        parsed_url = parsed_url._replace(netloc=parsed_url.netloc[4:])
    
    # Handle GitHub URLs specially
    if parsed_url.netloc == 'github.com':
        cleaned_url = parsed_url.path.lstrip('/')
    else:
        cleaned_url = urlunparse(parsed_url)
    
    logging.debug(f"Cleaned git URL: {cleaned_url}")
    return cleaned_url