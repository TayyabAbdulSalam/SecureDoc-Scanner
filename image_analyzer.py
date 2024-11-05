#!/usr/bin/python3

import os
import re
import io
import sys
import logging
import requests
import subprocess
from PIL import Image
from fpdf import FPDF

VIRUSTOTAL_API_KEY = 'eb9084d6a53acc6a1bb1202b56f15ee9f51980d4cb94fe9e4df94b87af779828'

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

# Redirect log messages to a buffer
output_buffer = io.StringIO()
log_handler = logging.StreamHandler(output_buffer)
logger.addHandler(log_handler)

def extract_with_steghide(image_path, output_file):
    """
    Use steghide to extract data from the image without requiring a password.
    """
    command = [
        'steghide', 'extract',
        '-sf', image_path,
        '-xf', output_file,
        '-f'
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def check_for_malicious_code(content):
    """
    Check the content for signs of malicious code.
    """
    patterns = [
        r'<\s*script[^>]*>.*?<\s*/\s*script\s*>',
        r'(?:\$|%)\{\s*[\w\.]+\s*\}',
        r'@\s*java\.lang\.Runtime\s*\.',
        r'\.exec\s*\(',
        r'@java\.lang\.Thread\s*\.\s*sleep',
        r'\b(?:eval|exec|system|popen|shell_exec|passthru|proc_open|cmd)\b',
        r'$_REQUEST\[\s*[\'"][\w]+[\'"]\s*\]',
        r'(?i)base64_decode\s*\(\s*["\'].*?["\']\s*\)',
        r'(?i)urlencode\s*\(\s*["\'].*?["\']\s*\)',
        r'(?i)(on[a-z]+)\s*=\s*["\'][^"\']*["\']',
        r'(?i)(javascript:|data:)',
        r'(\||;|&)\s*(ls|dir|cat|echo|wget|curl|rm|shutdown|reboot)\s*',
        r'<!--.*?-->',
        r'(?i)(select|insert|update|delete|drop|union|--|#)\s',
        r'\b(?:call_user_func|call_user_func_array|create_function)\s*\(',
        r'(?i)eval\s*\(\s*base64_decode\s*\(\s*["\'].*?["\']\s*\)\s*\)',
        r'(?i)(eval|setTimeout|setInterval)\s*\(\s*["\'].*?["\']\s*\)',
    ]

    for pattern in patterns:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            return True
    return False

def detect_reverse_shell(image_path):
    """
    Check if the file is a valid image and contains reverse shell payload.
    """
    try:
        with Image.open(image_path) as img:
            if img.format.lower() not in ['jpeg', 'png', 'svg', 'bmp', 'gif', 'tiff', 'webp', 'jp2']:
                return False
    except Exception:
        return False

    with open(image_path, 'rb') as f:
        data = f.read()
        
    patterns = [b'socket.socket', b'subprocess.call', b'/bin/sh', b'-i', b'1337']
    for pattern in patterns:
        if pattern in data:
            return True
    return False
    
def scan_with_virustotal(file_path):
    """
    Scan the file with VirusTotal.
    """
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, file)}
        response = requests.post(url, headers=headers, files=files)
    if response.status_code == 200:
        file_id = response.json()['data']['id']
        return check_virustotal_report(file_id)
    else:
        print("VirusTotal scan failed.")
        return None

def check_virustotal_report(file_id):
    """
    Check the VirusTotal report for the file.
    """
    url = f'https://www.virustotal.com/api/v3/analyses/{file_id}'
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result['data']['attributes']['status'] == 'completed':
                stats = result['data']['attributes']['stats']
                return stats['malicious'], stats['undetected'], stats['suspicious']
        else:
            print("Error checking VirusTotal report.")
            return None

def detect_malicious_image_format(image_path):
    """
    Check for various signs of malicious image formats.
    """
    try:
        with Image.open(image_path) as img:
            # Perform checks for known vulnerabilities or anomalies
            if img.format.lower() in ['jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'svg']:
                # Example: Check for unusual size, dimensions, or metadata
                if img.size[0] * img.size[1] > 1000000:  # Example: Very large images
                    return True
                
                # Further checks for suspicious metadata could be added here
                # Example: Check for suspicious comments in JPEG files
                if img.format.lower() == 'jpeg':
                    for tag, value in img.getexif().items():
                        if tag in [0x9286, 0x927C]:  # UserComment, Make
                            if re.search(r'(?i)(malicious|exploit)', str(value)):
                                return True

                # Further analysis can be added as needed
    except Exception:
        return False
    return False

def print_image_properties(image_path):
    """
    Print basic properties of the image (dimensions, format, mode, and size in bytes).
    """
    try:
        with Image.open(image_path) as img:
            print(f"Properties for {image_path}:")
            print(f"  Format: {img.format}")
            print(f"  Dimensions: {img.size[0]}x{img.size[1]}")
            print(f"  Mode: {img.mode}")
            print(f"  Size: {os.path.getsize(image_path)} bytes")
    except Exception as e:
        print(f"Could not retrieve properties for {image_path}: {e}")

def print_image_metadata(image_path):
    """
    Print the metadata of the image.
    """
    try:
        with Image.open(image_path) as img:
            info = img.info
            print("Metadata:")
            for key, value in info.items():
                print(f"  {key}: {value}")

            # Additionally print EXIF data if available
            exif_data = img.getexif()
            if exif_data:
                print("  EXIF Data:")
                for tag, val in exif_data.items():
                    print(f"    {tag}: {val}")

    except Exception as e:
        print(f"Could not retrieve metadata for {image_path}: {e}")

# Function to generate the PDF report
def generate_pdf_report(output_text, file_name="image_analysis_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 10, output_text)
    pdf.output(file_name)
    print(f"PDF report saved as {file_name}")

def detect_steganography_with_user_input():
    global orginal_stdout
    sys.stdout = original_stdout

    image_paths = input("Enter the paths to the suspected images (comma separated): ").strip().split(',')

    sys.stdout = output_buffer

    extracted_file_path = 'extracted_data.txt'

    for image_path in image_paths:
        image_path = image_path.strip()
        if not os.path.exists(image_path):
            print(f"Suspected image not found: {image_path}")
            continue

        print(f"\nProcessing {image_path}...")
        
        # Display image properties first
        print_image_properties(image_path)
        
        # Then display image metadata
        print_image_metadata(image_path)

        malicious_found = False

        # Check for reverse shell in the image
        if detect_reverse_shell(image_path):
            print("Malicious Content detected in the image!")
            malicious_found = True
        
        # Scan the original image with VirusTotal
        vt_result = scan_with_virustotal(image_path)
        if vt_result:
            malicious, undetected, suspicious = vt_result
            print(f"VirusTotal results for {image_path} (original image):")
            print(f"  Malicious: {malicious}")
            print(f"  Undetected: {undetected}")
            print(f"  Suspicious: {suspicious}")
            if malicious > 0 or suspicious > 0:
                malicious_found = True
        else:
            print("VirusTotal did not detect any malware in the original image.")
        
        # Check for signs of malicious image formats
        if detect_malicious_image_format(image_path):
            print("Malicious image format detected!")
            malicious_found = True

        if malicious_found:
            print(f"The image {image_path} is malicious.")
            continue

        # Extract hidden data from the suspected image
        if extract_with_steghide(image_path, extracted_file_path):
            print("Data extracted successfully.")
            with open(extracted_file_path, 'r', errors='ignore') as file:
                content = file.read()
            
            if check_for_malicious_code(content):
                print("Malicious code detected in the extracted data!")
                malicious_found = True
            else:
                print("No malicious code detected in the extracted data.")
            
            os.remove(extracted_file_path)
        else:
            print("No hidden data found or extraction failed.")
        
        if malicious_found:
            print(f"The image {image_path} is malicious.")
        else:
            print(f"No threat found in the image {image_path}.")

if __name__ == "__main__":
    output_buffer = io.StringIO()  # Create a buffer to capture printed output
    original_stdout = sys.stdout  # Save the original stdout
    sys.stdout = output_buffer  # Redirect stdout to the buffer

    # Run the analysis function and print debugging messages
    logger.info("Starting analysis...")  # Debugging message
    try:
        detect_steganography_with_user_input()  # Call your analysis function
    except Exception as e:
        logger.error(f"Error during analysis: {e}")  # Catch any errors
    logger.info("Analysis completed.")  # Debugging message

    # Restore the default stdout
    sys.stdout = original_stdout

    # Get the output text from the buffer and strip it
    output_text = output_buffer.getvalue().strip()

    # Debugging: Print the captured output in the terminal
    print("Captured Output for PDF:\n", output_text)

    # Ask the user if they want to generate a report
    generate_report = input("Would you like to generate a PDF report? (Y/n): ").strip().lower()
    if generate_report == 'y':
        if output_text:  # Check if output_text is not empty
            generate_pdf_report(output_text)
        else:
            print("No analysis output to generate a report.")
